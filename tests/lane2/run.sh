#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Lane 2 semantic-engine FP/FN corpus harness.
#
#   tests/lane2/run.sh                   # shadow mode (the shipped posture)
#   MODE=enforce tests/lane2/run.sh      # enforce mode (rollout_bps = 10000)
#   MODE=shadow,enforce tests/lane2/run.sh
#
# Brings up Postgres, a trivial origin and prx-waf; replays
# `tests/lane2/corpus/*.jsonl` at it; classifies the outcome into false
# negatives and false positives, split by attack family, by detector and by
# rule; and tears everything down again. Nothing is left running and nothing is
# written outside $WORK except the reports, which land in $OUT.
#
# ── Why this exists ──────────────────────────────────────────────────────────
# The Lane 2 semantic engine ships enabled, in `log_only`, with `rollout_bps = 0`
# — so it has never blocked anything. The blocker is not capability, it is
# evidence: nobody can say what turning it up would cost, because nobody has
# measured what it does to benign traffic. `tests/ftw/` answered that question
# for the CRS check and is the reason that number can be moved deliberately.
# This is the same instrument pointed at the other lane.
#
# ── What is measured ─────────────────────────────────────────────────────────
# Lane 2 and nothing else. The generated host turns OFF every Lane 1 detector
# (sqli/xss/rce/dir_traversal/bot/scan/sensitive) and the OWASP CRS check, which
# is not merely for attribution: Lane 1 runs FIRST and short-circuits on a hit
# (content_security/mod.rs `evaluate_scoped`), so with Lane 1 on, most of the
# attack corpus would never reach Lane 2 at all and the measurement would be of
# Lane 1. Rate limiting is off too (~400 requests, and the auto-ban would poison
# the run).
#
# The `[content_security]` block itself is COPIED OUT of `configs/default.toml`
# rather than restated here, so the run always measures the posture that actually
# ships. Every override the harness applies is a single line substitution that
# must match exactly once, and the script dies if `default.toml` ever stops
# containing the line being replaced — a config drift cannot silently change what
# is being measured.
#
# ── The two modes ────────────────────────────────────────────────────────────
# MODE=shadow (default) — the shipped `log_only` posture, verbatim. Verdicts come
#   from the `semantic_observations` rows the lane persists for every request
#   that produced a signal. This is the detection-quality number and the only one
#   carrying per-detector / per-rule attribution.
#
# MODE=enforce — `enforcement_mode = "enforce"` and `rollout_bps = 10000`, i.e.
#   the far end of the rollout dial. Verdicts come from HTTP status codes. This
#   is the blocking decision: a benign request that returns 403 here is an outage
#   that the shipped posture is hiding.
#
#   Two further overrides are needed for enforce mode to measure anything, and
#   both are recorded in the report because they are departures from the shipped
#   config:
#     * `breaker.window_secs` 300 -> 1. The restart shadow latch holds
#       enforcement at `Log` until one breaker window has elapsed since process
#       start (mod.rs `enforcement_warmed_up`). At the shipped 300 s the harness
#       would measure five minutes of nothing.
#     * `breaker.min_samples` 200 -> 1000000. The anomaly-rate breaker counts a
#       Block as an anomaly sample; an attack corpus is ~100 % anomalies by
#       construction, so at the shipped 200 the breaker would trip part-way
#       through and the second half of the corpus would be measured with
#       enforcement already suppressed.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"

POSTGRES_IMAGE="${POSTGRES_IMAGE:-docker.io/library/postgres:16}"

MODE="${MODE:-shadow}"                        # shadow | enforce | shadow,enforce
WORK="${WORK:-${TMPDIR:-/tmp}/prx-waf-lane2}"
OUT="${OUT:-$WORK/reports}"
SRC="${SRC:-$REPO_ROOT}"
PRXWAF_BIN="${PRXWAF_BIN:-}"
HOST_NAME="${HOST_NAME:-lane2.test}"
# Deliberately an uncommon port block: tests/ftw/ owns 189xx/199xx and a second
# harness running concurrently on the same box must not be measured instead.
WAF_PORT="${WAF_PORT:-17311}"
WAF_TLS_PORT="${WAF_TLS_PORT:-17344}"
API_PORT="${API_PORT:-17399}"
BACKEND_PORT="${BACKEND_PORT:-17388}"
PG_PORT="${PG_PORT:-15477}"
PG_CONTAINER="${PG_CONTAINER:-prx-waf-lane2-pg}"
KEEP="${KEEP:-0}"
SKIP_POSTGRES="${SKIP_POSTGRES:-0}"
BASELINE="${BASELINE:-}"
RECORDED_FROM="${RECORDED_FROM:-PLACEHOLDER-SHA}"

CONTAINER_CLI="${CONTAINER_CLI:-}"
if [ -z "$CONTAINER_CLI" ]; then
  if command -v podman >/dev/null 2>&1; then CONTAINER_CLI=podman
  elif command -v docker >/dev/null 2>&1; then CONTAINER_CLI=docker
  else echo "need podman or docker" >&2; exit 1; fi
fi

log() { printf '\033[1;36m[lane2]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31m[lane2] %s\033[0m\n' "$*" >&2; exit 1; }

# Pingora treats SIGTERM as *graceful* and keeps the process alive for its
# shutdown timeout, so a plain `kill; wait` hangs between modes and leaves a
# process holding the port. SIGINT is the fast path; escalate to SIGKILL.
WAF_PID=""
BACKEND_PID=""
stop_waf() {
  [ -n "${WAF_PID:-}" ] || return 0
  kill -INT "$WAF_PID" 2>/dev/null || true
  for _ in $(seq 1 20); do
    kill -0 "$WAF_PID" 2>/dev/null || break
    sleep 0.5
  done
  kill -9 "$WAF_PID" 2>/dev/null || true
  wait "$WAF_PID" 2>/dev/null || true
  WAF_PID=""
}

teardown() {
  local rc=$?
  if [ "$KEEP" = "1" ]; then
    log "KEEP=1 — leaving waf(pid=$WAF_PID) backend(pid=$BACKEND_PID) $PG_CONTAINER up"
    return $rc
  fi
  stop_waf
  [ -n "$BACKEND_PID" ] && kill "$BACKEND_PID" 2>/dev/null || true
  sleep 0.3
  [ -n "$BACKEND_PID" ] && kill -9 "$BACKEND_PID" 2>/dev/null || true
  [ "$SKIP_POSTGRES" = "1" ] || "$CONTAINER_CLI" rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true
  return $rc
}
trap teardown EXIT

mkdir -p "$WORK" "$OUT"

# Pingora retries a busy listen socket forever instead of failing, so a stranger
# answering on $WAF_PORT would be measured instead of the WAF.
port_busy() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
PORTS_TO_CHECK=("$WAF_PORT" "$WAF_TLS_PORT" "$API_PORT" "$BACKEND_PORT")
[ "$SKIP_POSTGRES" = "1" ] || PORTS_TO_CHECK+=("$PG_PORT")
for p in "${PORTS_TO_CHECK[@]}"; do
  if port_busy "$p"; then
    die "port $p is already in use — set WAF_PORT / WAF_TLS_PORT / API_PORT / BACKEND_PORT / PG_PORT"
  fi
done

CORPUS=("$SCRIPT_DIR"/corpus/*.jsonl)
[ -e "${CORPUS[0]}" ] || die "no corpus files in $SCRIPT_DIR/corpus/"

# ── 1. prx-waf binary ────────────────────────────────────────────────────────
if [ -z "$PRXWAF_BIN" ]; then
  log "building prx-waf (release) from $SRC"
  ( cd "$SRC" && CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$SRC/target}" \
      cargo build --release -p prx-waf )
  PRXWAF_BIN="${CARGO_TARGET_DIR:-$SRC/target}/release/prx-waf"
fi
[ -x "$PRXWAF_BIN" ] || die "prx-waf binary not found: $PRXWAF_BIN"

# ── 2. Postgres ──────────────────────────────────────────────────────────────
if [ "$SKIP_POSTGRES" = "1" ]; then
  log "SKIP_POSTGRES=1 — using the Postgres already on :$PG_PORT"
else
  log "starting postgres ($PG_CONTAINER on :$PG_PORT)"
  "$CONTAINER_CLI" rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true
  "$CONTAINER_CLI" run -d --name "$PG_CONTAINER" \
    -e POSTGRES_USER=prx_waf -e POSTGRES_PASSWORD=prx_waf -e POSTGRES_DB=prx_waf \
    -p "127.0.0.1:$PG_PORT:5432" "$POSTGRES_IMAGE" >/dev/null
  for _ in $(seq 1 60); do
    "$CONTAINER_CLI" exec "$PG_CONTAINER" pg_isready -U prx_waf >/dev/null 2>&1 && break
    sleep 1
  done
  "$CONTAINER_CLI" exec "$PG_CONTAINER" pg_isready -U prx_waf >/dev/null 2>&1 \
    || die "postgres did not become ready"
fi

export DATABASE_URL="postgresql://prx_waf:prx_waf@127.0.0.1:$PG_PORT/prx_waf"

# Read one JSON aggregate out of the database. Uses psql inside the container we
# own, and the host psql otherwise.
psql_json() {                      # $1 = SQL returning a single json value, $2 = out file
  local sql="$1" dst="$2"
  if [ "$SKIP_POSTGRES" = "1" ]; then
    command -v psql >/dev/null 2>&1 || die "SKIP_POSTGRES=1 needs a host psql to read results"
    psql "$DATABASE_URL" -At -c "$sql" >"$dst"
  else
    "$CONTAINER_CLI" exec "$PG_CONTAINER" psql -U prx_waf -d prx_waf -At -c "$sql" >"$dst"
  fi
  # `json_agg` over an empty set is NULL, which psql prints as an empty line.
  [ -s "$dst" ] && [ "$(head -c 4 "$dst")" != "" ] || echo '[]' >"$dst"
}

reset_tables() {
  local sql='TRUNCATE semantic_observations, security_events;'
  if [ "$SKIP_POSTGRES" = "1" ]; then
    psql "$DATABASE_URL" -q -c "$sql" >/dev/null 2>&1 || true
  else
    "$CONTAINER_CLI" exec "$PG_CONTAINER" psql -U prx_waf -d prx_waf -q -c "$sql" >/dev/null 2>&1 || true
  fi
}

# ── 3. Origin ────────────────────────────────────────────────────────────────
# A three-line reflector-free origin. The corpus asserts nothing about the
# response body, so there is no reason to pull in a Go toolchain for it: every
# request must simply reach a 200 when the WAF lets it through, so that a 403 in
# enforce mode can only have come from the WAF.
cat >"$WORK/origin.py" <<'PY'
import http.server, socketserver, sys

class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _serve(self):
        length = int(self.headers.get("content-length") or 0)
        if length:
            self.rfile.read(length)
        body = b"ok"
        self.send_response(200)
        self.send_header("content-type", "text/plain")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = _serve

    def log_message(self, *_args):
        pass

class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

with S(("127.0.0.1", int(sys.argv[1])), H) as srv:
    srv.serve_forever()
PY
log "starting origin on :$BACKEND_PORT"
python3 "$WORK/origin.py" "$BACKEND_PORT" >"$WORK/origin.log" 2>&1 &
BACKEND_PID=$!
for _ in $(seq 1 40); do
  port_busy "$BACKEND_PORT" && break
  sleep 0.25
done
port_busy "$BACKEND_PORT" || die "origin did not come up (see $WORK/origin.log)"

export JWT_SECRET="lane2-harness-$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
export MASTER_KEY="lane2-harness-$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
export ADMIN_PASSWORD="lane2-harness-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"
export RUST_LOG="${RUST_LOG:-warn}"

# ── Config generation ────────────────────────────────────────────────────────
# The `[content_security]` block is lifted verbatim out of configs/default.toml.
# See the header: restating it here would let the harness and the shipped
# posture drift apart without anyone noticing, which would make every number
# below a measurement of a config nobody runs.
extract_content_security() {        # $1 = mode, writes the block on stdout
  python3 - "$SRC/configs/default.toml" "$1" <<'PY'
import re, sys

path, mode = sys.argv[1], sys.argv[2]
with open(path, encoding="utf-8") as fh:
    lines = fh.read().splitlines()

start = None
for i, line in enumerate(lines):
    if line.strip() == "[content_security]":
        start = i
        break
if start is None:
    sys.exit("configs/default.toml has no [content_security] section")

# Everything from [content_security] up to the next top-level table that is not
# one of its sub-tables.
end = len(lines)
for i in range(start + 1, len(lines)):
    s = lines[i].strip()
    if s.startswith("[") and not s.startswith("[content_security"):
        end = i
        break
block = lines[start:end]

if mode == "enforce":
    # Each substitution must match exactly once. A default.toml that stops
    # carrying the line being replaced is a hard error, not a silent no-op:
    # a missed substitution here would report "enforce mode blocks nothing"
    # and look like a detection result rather than a harness bug.
    subs = [
        (r'^enforcement_mode\s*=\s*"log_only"', 'enforcement_mode = "enforce"'),
        (r'^rollout_bps\s*=\s*0\b', "rollout_bps = 10000"),
        # See the run.sh header for why the breaker has to be neutralised.
        (r'^window_secs\s*=\s*300\b', "window_secs = 1"),
        (r'^min_samples\s*=\s*200\b', "min_samples = 1000000"),
        (r'^anomaly_rate_threshold\s*=\s*0\.05\b', "anomaly_rate_threshold = 1.0"),
        (r'^cooldown_secs\s*=\s*900\b', "cooldown_secs = 1"),
    ]
    for pattern, replacement in subs:
        hits = [i for i, line in enumerate(block) if re.match(pattern, line.strip())]
        if len(hits) != 1:
            sys.exit(
                f"configs/default.toml drift: /{pattern}/ matched {len(hits)} lines in "
                "[content_security]; the enforce-mode override can no longer be applied"
            )
        indent = block[hits[0]][: len(block[hits[0]]) - len(block[hits[0]].lstrip())]
        block[hits[0]] = f"{indent}{replacement}   # OVERRIDDEN by tests/lane2/run.sh"

print("\n".join(block))
PY
}

gen_config() {                      # $1 = mode, $2 = output path
  local mode="$1" dst="$2"
  {
    cat <<EOF
# Generated by tests/lane2/run.sh — do not edit, do not commit.
# Lane 2 corpus harness, $mode mode.
[proxy]
listen_addr = "127.0.0.1:$WAF_PORT"
listen_addr_tls = "127.0.0.1:$WAF_TLS_PORT"
# The per-case loopback source address is the join key between a corpus row and
# its observation row, and several benign corpus rows deliberately carry their
# own X-Forwarded-For. Trusting proxy headers would let the corpus rewrite its
# own join key.
trust_proxy_headers = false
smuggling_detection = true

[api]
listen_addr = "127.0.0.1:$API_PORT"

[storage]
database_url = "$DATABASE_URL"
max_connections = 5

# Response caching off: a cached 200 would mask a later block decision.
[cache]
enabled = false
max_size_mb = 1
default_ttl_secs = 0
max_ttl_secs = 0

# Nothing but Lane 2 is being measured, so nothing but Lane 2 is loaded.
[rules]
dir = "rules/"
hot_reload = false
enable_builtin_owasp = false
enable_builtin_bot = false
enable_builtin_scanner = false

EOF
    extract_content_security "$mode"
    cat <<EOF

[[hosts]]
host = "$HOST_NAME"
port = 80
remote_host = "127.0.0.1"
remote_port = $BACKEND_PORT
guard_status = true
# false in both modes. log_only_mode is the per-host total kill switch and
# downgrades an enforced Lane 2 Block to LogOnly, which in enforce mode would
# silently measure shadow behaviour instead.
log_only_mode = false
[hosts.defense_config]
# Lane 1 runs BEFORE Lane 2 and short-circuits on a hit, so leaving any of these
# on would mean measuring Lane 1. The OWASP CRS check is off for the same reason
# tests/ftw/ turns Lane 1 and Lane 2 off: a hit must be attributable to exactly
# one engine.
bot = false
sqli = false
xss = false
scan = false
rce = false
sensitive = false
dir_traversal = false
owasp_set = false
# ~400 requests; the CC auto-ban would poison the second half of the run.
cc = false
owasp_paranoia = 1
EOF
  } >"$dst"
}

# ── Run one mode ─────────────────────────────────────────────────────────────
run_mode() {
  local mode="$1"
  local cfg="$WORK/prx-waf-$mode.toml"
  local waflog="$WORK/prx-waf-$mode.log"
  local results="$OUT/results-$mode.json"
  local obs="$OUT/observations-$mode.json"
  local events="$OUT/events-$mode.json"

  gen_config "$mode" "$cfg"

  log "$mode: migrating database"
  ( cd "$SRC" && "$PRXWAF_BIN" --config "$cfg" migrate ) >"$WORK/migrate-$mode.log" 2>&1 \
    || die "migration failed, see $WORK/migrate-$mode.log"
  reset_tables

  log "$mode: starting prx-waf on :$WAF_PORT"
  ( cd "$SRC" && exec "$PRXWAF_BIN" --config "$cfg" run ) >"$waflog" 2>&1 &
  WAF_PID=$!
  local ready=0
  for _ in $(seq 1 60); do
    if curl -s -o /dev/null -H "Host: $HOST_NAME" "http://127.0.0.1:$WAF_PORT/"; then
      ready=1; break
    fi
    kill -0 "$WAF_PID" 2>/dev/null || break
    sleep 0.5
  done
  [ "$ready" = "1" ] || { tail -40 "$waflog" >&2; die "prx-waf did not come up (see $waflog)"; }

  # In enforce mode the restart shadow latch holds enforcement at Log until one
  # breaker window has elapsed since process start. The window is overridden to
  # 1 s; wait it out, or the first requests would be measured in shadow.
  if [ "$mode" = "enforce" ]; then
    sleep 3
  fi

  # Sanity gate. A harness that is not wired to the engine reports a beautiful
  # 0 % FP rate, so prove the lane is alive before believing anything. The probe
  # is a plain SQLi in a query string with every Lane 1 detector and the CRS
  # check off — only Lane 2 can produce a verdict for it.
  local benign attack
  benign=$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $HOST_NAME" \
    "http://127.0.0.1:$WAF_PORT/?hello=world")
  attack=$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $HOST_NAME" \
    "http://127.0.0.1:$WAF_PORT/?id=1%20UNION%20SELECT%20NULL,NULL,NULL--")
  log "$mode: sanity — benign=$benign attack=$attack"
  [ "$benign" = "200" ] || die "sanity: benign request returned $benign, expected 200"
  if [ "$mode" = "enforce" ]; then
    [ "$attack" = "403" ] || die "sanity: enforce mode must block a UNION SELECT, got $attack"
  else
    [ "$attack" = "200" ] || die "sanity: shadow mode must not block, but got $attack"
    local seen=0
    for _ in $(seq 1 40); do
      psql_json "select coalesce(json_agg(t),'[]'::json) from (select 1 from semantic_observations limit 1) t" \
        "$WORK/sanity-$mode.json"
      if [ "$(cat "$WORK/sanity-$mode.json")" != "[]" ]; then seen=1; break; fi
      sleep 0.25
    done
    [ "$seen" = "1" ] || die "sanity: the semantic lane wrote no observation for a UNION SELECT — Lane 2 is not running"
    log "$mode: sanity — the semantic lane records observations"
  fi
  # The sanity probe's own rows must not enter the measurement.
  reset_tables

  log "$mode: replaying corpus (${#CORPUS[@]} files)"
  python3 "$SCRIPT_DIR/send.py" \
    --corpus "${CORPUS[@]}" \
    --dest 127.0.0.1 --port "$WAF_PORT" --host-header "$HOST_NAME" \
    --out "$results"

  # The observation sink is a bounded MPSC drained by one background worker
  # (semantic_sink.rs), so the rows land asynchronously. Wait for the count to
  # stop moving rather than sleeping a guessed interval.
  log "$mode: waiting for the observation sink to drain"
  local prev=-1 now=0 stable=0
  for _ in $(seq 1 120); do
    psql_json "select coalesce(json_agg(t),'[]'::json) from (select count(*) as n from semantic_observations) t" \
      "$WORK/count-$mode.json"
    now=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))[0]['n'])" "$WORK/count-$mode.json")
    if [ "$now" = "$prev" ]; then
      stable=$((stable + 1))
      [ "$stable" -ge 3 ] && break
    else
      stable=0
    fi
    prev="$now"
    sleep 0.5
  done
  log "$mode: $now observation rows"

  psql_json "select coalesce(json_agg(t),'[]'::json) from (
      select client_ip, scope, request_score, recommendation, degraded, exhausted, observations
      from semantic_observations) t" "$obs"
  psql_json "select coalesce(json_agg(t),'[]'::json) from (
      select client_ip, method, path, rule_id, rule_name, action
      from security_events) t" "$events"

  log "$mode: classifying"
  local extra=()
  [ -n "$BASELINE" ] && extra+=(--baseline "$BASELINE")
  set +e
  python3 "$SCRIPT_DIR/classify.py" \
    --results "$results" \
    --observations "$obs" \
    --events "$events" \
    --mode "$mode" \
    --engine-src "$SRC" \
    --recorded-from "$RECORDED_FROM" \
    --json-out "$OUT/report-$mode.json" \
    "${extra[@]}" | tee "$OUT/report-$mode.txt"
  local rc=${PIPESTATUS[0]}
  set -e

  stop_waf
  [ "$rc" = "0" ] || die "$mode regressed against $BASELINE"
}

IFS=',' read -r -a MODES <<<"$MODE"
for m in "${MODES[@]}"; do
  case "$m" in
    shadow|enforce) run_mode "$m" ;;
    *) die "MODE must be shadow and/or enforce, got '$m'" ;;
  esac
done

log "reports in $OUT"
