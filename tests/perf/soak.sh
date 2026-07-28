#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# prx-waf memory-shape harness: does sustained attack traffic converge?
#
#   tests/perf/soak.sh                        # shipping posture, 10 min, saturating
#   MINUTES=20 tests/perf/soak.sh
#   RATE=2000 MINUTES=10 tests/perf/soak.sh   # rate-limited attacker
#   POSTURE=lane2 tests/perf/soak.sh          # a control that writes nothing
#
# Writes one CSV row per second to $OUT/<label>.csv and a one-line verdict.
#
# ── Why this is not run.sh ───────────────────────────────────────────────────
# run.sh answers "what does a posture cost per request". It runs each cell for
# ten seconds and reports the PEAK RSS it saw, which is the right summary for a
# throughput table and the wrong one for this question entirely: a peak is one
# number, and the question here is the SHAPE of a curve.
#
# `tests/perf/RESULTS.md` §6 is explicit that it could not answer this —
# "whether it plateaus or continues is not established by this measurement" —
# because ten seconds cannot distinguish
#
#   converged   RSS rises to a working set and stays there. The write path
#               keeps up, or its queue is bounded and the bound is reached.
#   bounded     RSS rises and then stops below some ceiling that is not the
#               working set — a queue cap, a drop policy. Distinguishable from
#               "converged" only by whether anything is being DROPPED.
#   unbounded   RSS keeps rising for as long as traffic keeps arriving. The
#               attacker, not the operator, chooses how much memory this
#               process uses, and the end of the curve is the OOM killer.
#
# Those three have the same first ten seconds and completely different
# operational meanings, so this harness samples a time series instead of a peak,
# runs for minutes instead of seconds, and reads the queue depth alongside the
# RSS so a plateau can be attributed rather than just observed.
#
# ── The abort ────────────────────────────────────────────────────────────────
# If the answer is "unbounded", running to completion means an OOM on a
# developer workstation with 30 GiB of RAM and other people's work on it. The
# run therefore stops itself at RSS_ABORT_MIB and records why. **An abort is a
# result, not a failure**: reaching a hard ceiling in a fraction of the planned
# window with the queue still rising is the strongest available evidence for the
# third shape, and it is reported as such.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"

# ── Knobs ────────────────────────────────────────────────────────────────────
POSTURE="${POSTURE:-full}"
MINUTES="${MINUTES:-10}"
# Requests per second the generator is allowed. Empty = unthrottled, i.e. as
# fast as $CONNECTIONS connections can push, which is the saturating flood
# RESULTS.md §6 measured. A number is the far more interesting experiment: it
# asks whether a MODEST attacker, one who is not even trying to saturate the
# proxy, can still make memory grow without bound.
RATE="${RATE:-}"
CONNECTIONS="${CONNECTIONS:-50}"
SAMPLE_SECS="${SAMPLE_SECS:-1}"
WARMUP="${WARMUP:-3}"
RSS_ABORT_MIB="${RSS_ABORT_MIB:-12288}"
LABEL="${LABEL:-$POSTURE-$([ -n "$RATE" ] && echo "${RATE}rps" || echo saturating)-${MINUTES}min}"

OHA_VERSION="${OHA_VERSION:-1.11.0}"
ALBEDO_VERSION="${ALBEDO_VERSION:-v0.3.0}"
POSTGRES_IMAGE="${POSTGRES_IMAGE:-docker.io/library/postgres:16}"

WORK="${WORK:-${TMPDIR:-/tmp}/prx-waf-soak}"
OUT="${OUT:-$SCRIPT_DIR/results/soak}"
SRC="${SRC:-$REPO_ROOT}"
PRXWAF_BIN="${PRXWAF_BIN:-}"
WAF_PORT="${WAF_PORT:-18901}"
WAF_TLS_PORT="${WAF_TLS_PORT:-18944}"
API_PORT="${API_PORT:-19911}"
# Not 9090. The shipped default is the port Prometheus itself listens on, and on
# this host it is already taken by an unrelated service.
METRICS_PORT="${METRICS_PORT:-19991}"
BACKEND_PORT="${BACKEND_PORT:-18988}"
PG_PORT="${PG_PORT:-15633}"
PG_CONTAINER="${PG_CONTAINER:-prx-waf-soak-pg}"
SKIP_POSTGRES="${SKIP_POSTGRES:-0}"

# Same pinning discipline as run.sh, and for the same reason: the generator, the
# origin and the subject share one host, and without disjoint core sets the
# subject's numbers absorb scheduler noise that has nothing to do with it.
PIN="${PIN:-1}"
WAF_CPUS="${WAF_CPUS:-0-3}"
ORIGIN_CPUS="${ORIGIN_CPUS:-4-9}"
LOAD_CPUS="${LOAD_CPUS:-10-15}"

log() { printf '\033[1;36m[soak]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31m[soak] %s\033[0m\n' "$*" >&2; exit 1; }

case "$MINUTES" in ''|*[!0-9.]*) die "MINUTES must be a number, got '$MINUTES'" ;; esac
case "$RATE" in ''|*[!0-9]*) [ -z "$RATE" ] || die "RATE must be an integer, got '$RATE'" ;; esac

pin() {                                # $1 = cpu list, rest = command
  local cpus="$1"; shift
  if [ "$PIN" = "1" ] && command -v taskset >/dev/null 2>&1; then
    taskset -c "$cpus" "$@"
  else
    "$@"
  fi
}

# What state was the tree in when this was measured?
#
# Scoped to the paths that decide what the binary and its rule set are, and
# deliberately NOT to the whole tree: this harness writes its own results back
# into `tests/perf/results/`, so a whole-tree check reports "MODIFIED" on every
# run after the first purely because the previous run's CSV is committed. That
# reads as "the sources were dirty" and it is not what happened. The question the
# reader needs answered is whether the SUBJECT matches the commit, so those are
# the paths that get checked.
INPUT_PATHS=(crates Cargo.toml Cargo.lock rules configs migrations)

worktree_state() {
  local tracked untracked
  tracked=0
  ( cd "$SRC" && git diff --quiet -- "${INPUT_PATHS[@]}" \
      && git diff --cached --quiet -- "${INPUT_PATHS[@]}" ) 2>/dev/null || tracked=1
  untracked="$( cd "$SRC" && git ls-files --others --exclude-standard -- "${INPUT_PATHS[@]}" 2>/dev/null | wc -l )"
  if [ "$tracked" = "1" ]; then
    echo "MODIFIED — tracked build inputs differ from the commit; this result is NOT reproducible from it"
  elif [ "${untracked:-0}" -gt 0 ]; then
    echo "build inputs clean; ${untracked} untracked file(s) under them"
  else
    echo "build inputs clean"
  fi
}

CONTAINER_CLI="${CONTAINER_CLI:-}"
if [ -z "$CONTAINER_CLI" ]; then
  if command -v podman >/dev/null 2>&1; then CONTAINER_CLI=podman
  elif command -v docker >/dev/null 2>&1; then CONTAINER_CLI=docker
  else die "need podman or docker"; fi
fi

# ── Teardown ─────────────────────────────────────────────────────────────────
WAF_PID=""
BACKEND_PID=""
LOAD_PID=""

stop_load() {
  [ -n "$LOAD_PID" ] || return 0
  kill "$LOAD_PID" 2>/dev/null || true
  wait "$LOAD_PID" 2>/dev/null || true
  LOAD_PID=""
}

# Pingora reads SIGTERM as graceful shutdown and lingers; SIGINT is its fast
# path. Escalate if even that does not land — a subject holding 12 GiB has a lot
# of allocator teardown to do and can outlive a polite request.
stop_waf() {
  [ -n "$WAF_PID" ] || return 0
  kill -INT "$WAF_PID" 2>/dev/null || true
  for _ in $(seq 1 40); do
    kill -0 "$WAF_PID" 2>/dev/null || break
    sleep 0.5
  done
  kill -9 "$WAF_PID" 2>/dev/null || true
  wait "$WAF_PID" 2>/dev/null || true
  WAF_PID=""
}

teardown() {
  local rc=$?
  stop_load
  stop_waf
  [ -n "$BACKEND_PID" ] && kill "$BACKEND_PID" 2>/dev/null || true
  sleep 0.3
  [ -n "$BACKEND_PID" ] && kill -9 "$BACKEND_PID" 2>/dev/null || true
  [ "$SKIP_POSTGRES" = "1" ] || "$CONTAINER_CLI" rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true
  return $rc
}
trap teardown EXIT

mkdir -p "$WORK" "$OUT"

port_busy() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
PORTS_TO_CHECK=("$WAF_PORT" "$WAF_TLS_PORT" "$API_PORT" "$BACKEND_PORT" "$METRICS_PORT")
[ "$SKIP_POSTGRES" = "1" ] || PORTS_TO_CHECK+=("$PG_PORT")
for p in "${PORTS_TO_CHECK[@]}"; do
  port_busy "$p" && die "port $p already in use"
done

command -v jq >/dev/null 2>&1 || die "jq is required"
command -v curl >/dev/null 2>&1 || die "curl is required"

# A generator left over from an earlier run is the one contaminant a free port
# check cannot see: it holds no listener, it just keeps sending. Refuse rather
# than measure two attackers and attribute the sum to one.
if pgrep -x oha >/dev/null 2>&1; then
  pgrep -ax oha >&2
  die "an 'oha' process is already running — a leftover generator would be measured as this run's traffic"
fi

# ── Tools ────────────────────────────────────────────────────────────────────
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
OHA_BIN="${OHA_BIN:-}"
if [ -z "$OHA_BIN" ]; then
  if command -v oha >/dev/null 2>&1 &&
     [ "$(oha --version 2>/dev/null | awk '{print $2}')" = "$OHA_VERSION" ]; then
    OHA_BIN="$(command -v oha)"
  elif [ -x "${TMPDIR:-/tmp}/prx-waf-perf/cargo/bin/oha" ]; then
    OHA_BIN="${TMPDIR:-/tmp}/prx-waf-perf/cargo/bin/oha"
  else
    log "installing oha $OHA_VERSION"
    cargo install oha --version "$OHA_VERSION" --locked --root "$WORK/cargo" >/dev/null
    OHA_BIN="$WORK/cargo/bin/oha"
  fi
fi
[ -x "$OHA_BIN" ] || die "oha not found: $OHA_BIN"

export GOPATH="${GOPATH:-$WORK/go}" GOBIN="${GOBIN:-$WORK/bin}"
mkdir -p "$GOBIN"
if [ ! -x "$GOBIN/albedo" ]; then
  if [ -x "${TMPDIR:-/tmp}/prx-waf-perf/bin/albedo" ]; then
    cp "${TMPDIR:-/tmp}/prx-waf-perf/bin/albedo" "$GOBIN/albedo"
  else
    command -v go >/dev/null 2>&1 || die "go toolchain required to install albedo"
    log "installing albedo@$ALBEDO_VERSION"
    go install "github.com/coreruleset/albedo@$ALBEDO_VERSION"
  fi
fi

if [ -z "$PRXWAF_BIN" ]; then
  log "building prx-waf (release) from $SRC"
  ( cd "$SRC" && CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$SRC/target}" \
      cargo build --release -p prx-waf )
  PRXWAF_BIN="${CARGO_TARGET_DIR:-$SRC/target}/release/prx-waf"
fi
[ -x "$PRXWAF_BIN" ] || die "prx-waf binary not found: $PRXWAF_BIN"
[ -d "$SRC/rules/owasp-crs" ] || die "$SRC/rules/owasp-crs missing (rules load relative to CWD)"

# ── Postgres ─────────────────────────────────────────────────────────────────
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
export JWT_SECRET="soak-$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
export MASTER_KEY="soak-$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
export ADMIN_PASSWORD="soak-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"
export RUST_LOG="${RUST_LOG:-warn}"

# ── Origin ───────────────────────────────────────────────────────────────────
log "starting albedo origin on :$BACKEND_PORT (cpus $ORIGIN_CPUS)"
(
  if [ "$PIN" = "1" ] && command -v taskset >/dev/null 2>&1; then
    exec taskset -c "$ORIGIN_CPUS" "$GOBIN/albedo" --bind 127.0.0.1 --port "$BACKEND_PORT"
  else
    exec "$GOBIN/albedo" --bind 127.0.0.1 --port "$BACKEND_PORT"
  fi
) >"$WORK/albedo.log" 2>&1 &
BACKEND_PID=$!
for _ in $(seq 1 30); do
  curl -sf "http://127.0.0.1:$BACKEND_PORT/capabilities" >/dev/null 2>&1 && break
  sleep 0.3
done
curl -sf "http://127.0.0.1:$BACKEND_PORT/capabilities" >/dev/null 2>&1 \
  || die "albedo did not come up (see $WORK/albedo.log)"

# ── Config ───────────────────────────────────────────────────────────────────
# Deliberately the same generator run.sh uses, posture for posture, so a soak
# row and a run.sh row describe the same binary in the same configuration and
# the two pages can be read against each other.
gen_config() {                         # $1 = posture, $2 = output path
  local posture="$1" dst="$2"
  local bot=false sqli=false xss=false scan=false rce=false sensitive=false
  local traversal=false owasp=false cc=false pl=1 cs_enabled=false

  case "$posture" in
    passthrough) ;;
    lane1) bot=true sqli=true xss=true scan=true rce=true sensitive=true traversal=true ;;
    crs-pl1) owasp=true pl=1 ;;
    lane2) cs_enabled=true ;;
    cc)    cc=true ;;
    full)  bot=true sqli=true xss=true scan=true rce=true sensitive=true traversal=true
           owasp=true pl=1 cc=true cs_enabled=true ;;
    *) die "unknown posture: $posture" ;;
  esac

  {
    cat <<EOF
# Generated by tests/perf/soak.sh — do not edit, do not commit.
# Posture: $posture
[proxy]
listen_addr = "127.0.0.1:$WAF_PORT"
listen_addr_tls = "127.0.0.1:$WAF_TLS_PORT"
trust_proxy_headers = false
smuggling_detection = true

[api]
listen_addr = "127.0.0.1:$API_PORT"

[metrics]
enabled = true
listen_addr = "127.0.0.1:$METRICS_PORT"

[storage]
database_url = "$DATABASE_URL"
max_connections = 20

[cache]
enabled = false
max_size_mb = 1
default_ttl_secs = 0
max_ttl_secs = 0

[geoip]
enabled = false

[rules]
dir = "rules/"
hot_reload = false
enable_builtin_owasp = $owasp
enable_builtin_bot = $bot
enable_builtin_scanner = $scan

[[hosts]]
host = "127.0.0.1"
port = $WAF_PORT
remote_host = "127.0.0.1"
remote_port = $BACKEND_PORT
guard_status = true
log_only_mode = false
[hosts.defense_config]
bot = $bot
sqli = $sqli
xss = $xss
scan = $scan
rce = $rce
sensitive = $sensitive
dir_traversal = $traversal
owasp_set = $owasp
owasp_paranoia = $pl
cc = $cc
EOF
    if [ "$cc" = "true" ]; then
      # The limiter must never fire: a soak that ends up measuring the 429 path
      # is measuring a request that was never inspected and never written down.
      cat <<'EOF'
cc_rps = 1000000.0
cc_burst = 2000000
cc_ban_threshold = 4294967295
EOF
    fi

    if [ "$cs_enabled" = "true" ]; then
      echo
      sed -n '/^\[content_security\]/,$p' "$SRC/configs/default.toml"
    else
      cat <<'EOF'

[content_security]
enabled = false
EOF
    fi
  } >"$dst"
}

CFG="$WORK/prx-waf-$POSTURE.toml"
WAFLOG="$WORK/prx-waf-$POSTURE.log"
gen_config "$POSTURE" "$CFG"

log "migrating database"
( cd "$SRC" && "$PRXWAF_BIN" --config "$CFG" migrate ) >"$WORK/migrate.log" 2>&1 \
  || die "migration failed, see $WORK/migrate.log"

log "starting prx-waf ($POSTURE) on :$WAF_PORT (cpus $WAF_CPUS)"
(
  cd "$SRC"
  if [ "$PIN" = "1" ] && command -v taskset >/dev/null 2>&1; then
    exec taskset -c "$WAF_CPUS" "$PRXWAF_BIN" --config "$CFG" run
  else
    exec "$PRXWAF_BIN" --config "$CFG" run
  fi
) >"$WAFLOG" 2>&1 &
WAF_PID=$!
ready=0
for _ in $(seq 1 90); do
  if curl -s -o /dev/null "http://127.0.0.1:$WAF_PORT/get"; then ready=1; break; fi
  kill -0 "$WAF_PID" 2>/dev/null || break
  sleep 0.5
done
[ "$ready" = "1" ] || { tail -40 "$WAFLOG" >&2; die "prx-waf did not come up (see $WAFLOG)"; }

UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
ATTACK_PATH="/get?id=1%27%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--"

# The same sanity gate run.sh applies. A soak against a posture that is not
# detecting anything measures an idle process and would "prove" convergence.
benign="$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" "http://127.0.0.1:$WAF_PORT/get?hello=world")"
attack="$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" "http://127.0.0.1:$WAF_PORT$ATTACK_PATH")"
log "sanity: benign=$benign attack=$attack"
[ "$benign" = "200" ] || die "sanity: benign request returned $benign, expected 200"
case "$POSTURE" in
  passthrough|cc) [ "$attack" != "403" ] || die "sanity: $POSTURE blocked a SQLi payload — detection is ON when it should be OFF" ;;
  lane1|crs-pl1|full) [ "$attack" = "403" ] || die "sanity: $POSTURE returned $attack for SQLi, expected 403" ;;
  lane2) [ "$attack" != "403" ] || die "sanity: lane2 blocked — expected the shipping shadow posture" ;;
esac

curl -sf "http://127.0.0.1:$METRICS_PORT/metrics" >/dev/null \
  || die "metrics endpoint is not answering on :$METRICS_PORT — this harness has nothing to read"

# ── Sampling ─────────────────────────────────────────────────────────────────
clk_tck="$(getconf CLK_TCK)"

cpu_ticks() {
  awk '{ n = split($0, f, ") "); split(f[n], g, " "); print g[12] + g[13] }' \
    "/proc/$1/stat" 2>/dev/null || echo 0
}
rss_kb_of() { awk '/^VmRSS:/{print $2}' "/proc/$1/status" 2>/dev/null || echo 0; }
thread_count() { ls "/proc/$1/task" 2>/dev/null | wc -l; }

# One scrape, reduced to the handful of series this question needs. `awk` over
# the text exposition rather than a Prometheus client, because adding a TSDB to
# a memory experiment would be adding a second memory consumer to it.
scrape() {
  curl -s --max-time 3 "http://127.0.0.1:$METRICS_PORT/metrics" 2>/dev/null | awk '
    /^prxwaf_queue_depth\{queue="attack_log"\}/            { q_attack = $2 }
    /^prxwaf_queue_depth\{queue="security_event"\}/        { q_secev  = $2 }
    /^prxwaf_queue_depth\{queue="semantic_observations"\}/ { q_obs    = $2 }
    /^prxwaf_queue_depth\{queue="semantic_events"\}/       { q_sem    = $2 }
    /^prxwaf_queue_depth\{queue="audit_log"\}/             { q_audit  = $2 }
    /^prxwaf_db_pool\{state="connections"\}/               { pool_c   = $2 }
    /^prxwaf_db_pool\{state="idle"\}/                      { pool_i   = $2 }
    /limit="attack_log"\}/                                 { d_attack = $2 }
    /limit="security_event"\}/                             { d_secev  = $2 }
    /limit="semantic_observations"\}/                      { d_obs    = $2 }
    /limit="semantic_events"\}/                            { d_sem    = $2 }
    /limit="audit_log"\}/                                  { d_audit  = $2 }
    /^prxwaf_requests_total\{.*action="block"\}/           { blocked += $2 }
    /^prxwaf_requests_total\{.*action="allow"\}/           { allowed += $2 }
    END {
      printf "%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n",
        q_attack+0, q_secev+0, q_obs+0, q_sem+0, q_audit+0,
        pool_c+0, pool_i+0,
        d_attack+0, d_secev+0, d_obs+0, d_sem+0, d_audit+0,
        blocked+0, allowed+0
    }'
}

CSV="$OUT/$LABEL.csv"
META="$OUT/$LABEL.json"
: >"$CSV"
echo "t_s,rss_kb,cpu_cores,threads,q_attack_log,q_security_event,q_semantic_obs,q_semantic_events,q_audit_log,pool_connections,pool_idle,drop_attack_log,drop_security_event,drop_semantic_obs,drop_semantic_events,drop_audit_log,requests_blocked,requests_allowed" >>"$CSV"

log "warmup ${WARMUP}s"
pin "$LOAD_CPUS" "$OHA_BIN" --no-tui --output-format json -c "$CONNECTIONS" \
  -z "${WARMUP}s" -H "User-Agent: $UA" "http://127.0.0.1:$WAF_PORT$ATTACK_PATH" \
  >/dev/null 2>&1 || true

DURATION_S="$(awk -v m="$MINUTES" 'BEGIN{printf "%d", m*60}')"
LOAD_BEFORE="$(awk '{print $1}' /proc/loadavg)"
log "load average before: $LOAD_BEFORE"
log "driving $POSTURE for ${MINUTES} min (${DURATION_S}s), rate=${RATE:-unthrottled}, c=$CONNECTIONS"
log "abort if RSS exceeds ${RSS_ABORT_MIB} MiB"

RATE_ARGS=()
[ -n "$RATE" ] && RATE_ARGS=(-q "$RATE")

# `exec` inside an explicit subshell, NOT the `pin` helper. Backgrounding a
# shell FUNCTION makes `$!` the subshell's pid, so `stop_load` would kill the
# wrapper and leave the generator running — which is not a tidiness problem, it
# is a correctness one: an orphaned generator from a finished run keeps loading
# the next run's WAF on the same port, and the second run then measures its own
# traffic plus a ghost. This harness produced exactly that once (a `RATE=2000`
# run that recorded 20,000 rps because the previous saturating run's generator
# was still alive), which is why the invariant is spelled out here rather than
# assumed. run.sh makes the same note about albedo.
(
  if [ "$PIN" = "1" ] && command -v taskset >/dev/null 2>&1; then
    exec taskset -c "$LOAD_CPUS" "$OHA_BIN" --no-tui --output-format json \
      -c "$CONNECTIONS" "${RATE_ARGS[@]}" -z "${DURATION_S}s" \
      -H "User-Agent: $UA" "http://127.0.0.1:$WAF_PORT$ATTACK_PATH"
  else
    exec "$OHA_BIN" --no-tui --output-format json \
      -c "$CONNECTIONS" "${RATE_ARGS[@]}" -z "${DURATION_S}s" \
      -H "User-Agent: $UA" "http://127.0.0.1:$WAF_PORT$ATTACK_PATH"
  fi
) >"$WORK/oha-$LABEL.json" 2>"$WORK/oha-$LABEL.err" &
LOAD_PID=$!
# Verify the claim rather than trust it: if `$!` is not the generator, every
# figure this run produces is contaminated and the run must not proceed.
sleep 1
LOAD_COMM="$(cat "/proc/$LOAD_PID/comm" 2>/dev/null || echo "gone")"
[ "$LOAD_COMM" = "oha" ] \
  || die "load generator pid $LOAD_PID is '$LOAD_COMM', not oha — stop_load would orphan it"

start_ticks="$(cpu_ticks "$WAF_PID")"
start_epoch="$(date +%s.%N)"
prev_ticks="$start_ticks"
prev_epoch="$start_epoch"
ABORTED=""
PEAK_RSS_KB=0
t=0

while :; do
  sleep "$SAMPLE_SECS"
  kill -0 "$WAF_PID" 2>/dev/null || { ABORTED="subject exited"; break; }

  now="$(date +%s.%N)"
  t="$(awk -v a="$start_epoch" -v b="$now" 'BEGIN{printf "%.1f", b-a}')"
  rss_kb="$(rss_kb_of "$WAF_PID")"
  [ -n "${rss_kb:-}" ] || rss_kb=0
  ticks="$(cpu_ticks "$WAF_PID")"
  cores="$(awk -v d="$((ticks - prev_ticks))" -v k="$clk_tck" -v a="$prev_epoch" -v b="$now" \
             'BEGIN{ e=b-a; if (e>0 && k>0) printf "%.3f", (d/k)/e; else print "0" }')"
  prev_ticks="$ticks"; prev_epoch="$now"
  threads="$(thread_count "$WAF_PID")"
  m="$(scrape)"
  echo "$t,$rss_kb,$cores,$threads,$m" >>"$CSV"

  [ "${rss_kb:-0}" -gt "$PEAK_RSS_KB" ] && PEAK_RSS_KB="$rss_kb"

  if [ "$((rss_kb / 1024))" -ge "$RSS_ABORT_MIB" ]; then
    ABORTED="RSS reached ${RSS_ABORT_MIB} MiB"
    log "!! abort: RSS $((rss_kb / 1024)) MiB at t=${t}s — stopping before the OOM killer does"
    break
  fi

  # Progress line every 15 samples so a long run is watchable without tailing
  # the CSV.
  if [ "$(awk -v t="$t" -v s="$SAMPLE_SECS" 'BEGIN{printf "%d", int(t/s) % 15}')" = "0" ]; then
    log "  t=${t}s rss=$((rss_kb / 1024))MiB cpu=${cores}c q=$(echo "$m" | cut -d, -f1)/$(echo "$m" | cut -d, -f2) pool=$(echo "$m" | cut -d, -f6)/$(echo "$m" | cut -d, -f7)idle"
  fi

  kill -0 "$LOAD_PID" 2>/dev/null || break
done

stop_load
LOAD_AFTER="$(awk '{print $1}' /proc/loadavg)"

# One last sample after the traffic stops: whether RSS comes back down says
# whether the growth was a queue that drained or memory that was never returned.
sleep 5
SETTLED_KB=0
kill -0 "$WAF_PID" 2>/dev/null && SETTLED_KB="$(rss_kb_of "$WAF_PID")"
echo "settled_after_load_stopped,$SETTLED_KB,,,,,,,,,,,,,,,," >>"$CSV"

jq -n \
  --arg label "$LABEL" --arg posture "$POSTURE" --arg rate "${RATE:-unthrottled}" \
  --argjson minutes "$MINUTES" --argjson connections "$CONNECTIONS" \
  --argjson sample_secs "$SAMPLE_SECS" --argjson abort_mib "$RSS_ABORT_MIB" \
  --arg aborted "${ABORTED:-}" --argjson peak_rss_kb "$PEAK_RSS_KB" \
  --argjson settled_rss_kb "${SETTLED_KB:-0}" --argjson observed_s "$t" \
  --arg load_before "$LOAD_BEFORE" --arg load_after "$LOAD_AFTER" \
  --arg tree "$(cd "$SRC" && git rev-parse HEAD 2>/dev/null || echo unknown)" \
  --arg dirty "$(worktree_state)" \
  --arg binary "$PRXWAF_BIN" \
  '{label:$label, posture:$posture, rate:$rate, minutes:$minutes,
    connections:$connections, sample_secs:$sample_secs, rss_abort_mib:$abort_mib,
    aborted:$aborted, peak_rss_kb:$peak_rss_kb, settled_rss_kb:$settled_rss_kb,
    observed_s:$observed_s, load_before:$load_before, load_after:$load_after,
    tree:$tree, worktree:$dirty, binary:$binary}' >"$META"

log "series: $CSV"
log "meta:   $META"
python3 "$SCRIPT_DIR/soak_shape.py" "$CSV" "$META"
