#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# prx-waf runtime performance harness.
#
#   tests/perf/run.sh                             # every posture, every workload
#   POSTURES=origin,passthrough tests/perf/run.sh # just the two references
#   WORKLOADS=get-small ROUNDS=1 tests/perf/run.sh
#   DURATION=30 CONNECTIONS=100 tests/perf/run.sh
#
# Brings up Postgres, an `albedo` origin and prx-waf, drives load with `oha`,
# writes one JSON record per (posture, workload, round) and prints a table.
# Nothing is left running afterwards.
#
# This harness is NOT a CI gate. See README.md, "Why this is not a gate".
#
# ── The measurement question ─────────────────────────────────────────────────
# "How much does the WAF cost" is meaningless without a reference, and one
# reference is not enough, because two different costs are being confused:
#
#   the proxy hop      accept, parse, route, pool an upstream connection,
#                      relay the response — paid by ANY reverse proxy
#   the detection      regex lanes, the CRS rule set, the semantic engine —
#                      paid only because this proxy is a WAF
#
# So the harness carries two references:
#
#   origin       load generator straight at albedo, no proxy in the path. Not a
#                competitor — a ceiling. Without it you cannot tell whether a
#                posture's number is the WAF's limit or the rig's limit, and
#                every conclusion below it is unfalsifiable.
#   passthrough  the real shipping prx-waf binary with every detector switched
#                off. This is the proxy hop on its own.
#
#   origin → passthrough   = the cost of putting a reverse proxy in the path
#   passthrough → posture  = the cost of that posture's detection, and nothing
#                            else
#
# Deliberately NOT the reference: nginx, or a hand-written bare Pingora proxy.
#   * nginx would answer a different question. The delta would fold "Rust
#     Pingora vs C nginx" into "detection cost", which is precisely the term we
#     are trying to isolate. It is a fine PRODUCT comparison and a bad
#     ATTRIBUTION baseline; it belongs in a separate exercise.
#   * a bare Pingora binary would be a second program with its own drift. Using
#     the shipping binary with detection off measures the code path that
#     actually runs in production, including whatever the WAF framework costs
#     before it consults a single rule — which is part of the honest answer.
#
# ── Layering ─────────────────────────────────────────────────────────────────
# Each posture adds exactly one layer to the one before it, so a subtraction
# attributes cost to a layer rather than to a lump sum:
#
#   origin        no proxy at all
#   passthrough   proxy, zero detection
#   lane1         + the native regex detectors (sqli/xss/rce/scan/traversal/…)
#   crs-pl1       + OWASP CRS at paranoia 1     (the shipping default level)
#   crs-pl2/pl4   + OWASP CRS at paranoia 2 / 4 (the paranoia cost curve)
#   lane2         + the Lane 2 semantic engine, shipping shadow posture
#   cc            + the per-IP rate limiter, on its own
#   full          lane1 + CRS PL1 + lane2 + cc — the shipping default
#
# CRS postures are cumulative over `passthrough`, NOT over `lane1`, so the CRS
# figure is not contaminated by Lane 1. `full` is the only posture that stacks
# everything, and it is the number an operator experiences.
#
# ── What is deliberately held constant ───────────────────────────────────────
# Response caching is OFF in every posture including `full`. A cache hit skips
# the upstream entirely and would make the WAF look FASTER than the origin it
# fronts — a real feature, but it would drown every detection delta this
# harness exists to measure. Same reasoning for the audit log and geoip.
# Measuring the cache is a separate question and needs a separate workload mix.
#
# Five of the six workloads are benign, because the clean path is the one
# ~all real traffic takes and the one a latency budget is spent on. `attack` is
# included and reported separately: it is the worst case for detection work,
# but it is NOT comparable to the benign rows — a blocked request never reaches
# the upstream, so it skips a hop the others pay for.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"

# ── Pins. A performance number is only comparable to another number produced
#    by the same generator at the same version against the same origin. ───────
OHA_VERSION="${OHA_VERSION:-1.11.0}"
ALBEDO_VERSION="${ALBEDO_VERSION:-v0.3.0}"     # same origin the CRS harness uses
POSTGRES_IMAGE="${POSTGRES_IMAGE:-docker.io/library/postgres:16}"

# ── Knobs ────────────────────────────────────────────────────────────────────
POSTURES="${POSTURES:-origin,passthrough,lane1,crs-pl1,crs-pl2,crs-pl4,lane2,cc,full}"
WORKLOADS="${WORKLOADS:-get-small,json-post,form-post,multipart,body-1mb,attack}"
ROUNDS="${ROUNDS:-3}"                          # per (posture, workload); median wins
DURATION="${DURATION:-10}"                     # seconds of measured load per round
WARMUP="${WARMUP:-3}"                          # seconds of unmeasured load first
CONNECTIONS="${CONNECTIONS:-50}"

# Two knobs that select a CONFIGURATION rather than a workload, because both
# defaults changed after the first matrix was recorded and a table that cannot
# state which side of the change it is on is not comparable to anything.
#
#   WORKER_THREADS         empty = the shipped default, i.e. `[proxy]
#                          worker_threads` unset, which follows the CPUs the
#                          process may use — under `taskset -c $WAF_CPUS` that
#                          is the size of the pinned set, not `nproc`. N pins
#                          the data plane to N threads; 1 reproduces every
#                          release before the key was wired up.
#   LANE1_MAX_BODY_BYTES   empty = the shipped default (65536). 0 restores the
#                          unbounded Lane 1 that shipped before it, which is
#                          the posture the pre-budget tables measured.
#
# Both are written into the generated TOML rather than exported, so the config
# file left in $WORK is a complete record of what was measured.
WORKER_THREADS="${WORKER_THREADS:-}"
LANE1_MAX_BODY_BYTES="${LANE1_MAX_BODY_BYTES:-}"

#   METRICS                empty = the shipped default, i.e. `[metrics] enabled
#                          = true`. 0 turns recording off entirely, which is the
#                          only way to measure what the recording itself costs:
#                          `full` against `full-nometrics` is the whole answer,
#                          and no code path differs between them except the
#                          `OnceLock` the record sites test.
METRICS="${METRICS:-}"

WORK="${WORK:-${TMPDIR:-/tmp}/prx-waf-perf}"
OUT="${OUT:-$WORK/reports}"
SRC="${SRC:-$REPO_ROOT}"
PRXWAF_BIN="${PRXWAF_BIN:-}"
WAF_PORT="${WAF_PORT:-18801}"
WAF_TLS_PORT="${WAF_TLS_PORT:-18844}"
API_PORT="${API_PORT:-19811}"
# Not the shipped default (127.0.0.1:9127): a harness that fights a real
# prx-waf, or a second harness, for the machine's one metrics socket fails in a
# way that looks like a WAF bug.
METRICS_PORT="${METRICS_PORT:-19891}"
BACKEND_PORT="${BACKEND_PORT:-18888}"
PG_PORT="${PG_PORT:-15533}"
PG_CONTAINER="${PG_CONTAINER:-prx-waf-perf-pg}"
SKIP_POSTGRES="${SKIP_POSTGRES:-0}"
KEEP="${KEEP:-0}"

# ── CPU pinning ──────────────────────────────────────────────────────────────
# Generator, origin and subject share one host, so without pinning they fight
# for the same cores and the "WAF cost" absorbs scheduler noise that has
# nothing to do with the WAF. Fixed, disjoint core sets make rounds repeatable.
# Set PIN=0 to measure without it (and expect wider spread between rounds).
PIN="${PIN:-1}"
WAF_CPUS="${WAF_CPUS:-0-3}"
ORIGIN_CPUS="${ORIGIN_CPUS:-4-9}"
LOAD_CPUS="${LOAD_CPUS:-10-15}"

log() { printf '\033[1;36m[perf]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31m[perf] %s\033[0m\n' "$*" >&2; exit 1; }

# A typo in either knob must not silently fall through to the shipped default:
# the whole point of them is to say which posture a table describes.
case "$WORKER_THREADS" in ''|[0-9]|[0-9][0-9]|[0-9][0-9][0-9]) ;;
  *) die "WORKER_THREADS must be a non-negative integer or empty, got '$WORKER_THREADS'" ;;
esac
case "$LANE1_MAX_BODY_BYTES" in ''|*[!0-9]*)
  [ -z "$LANE1_MAX_BODY_BYTES" ] ||
    die "LANE1_MAX_BODY_BYTES must be a non-negative integer or empty, got '$LANE1_MAX_BODY_BYTES'" ;;
esac
case "$METRICS" in ''|0|1) ;;
  *) die "METRICS must be 0, 1 or empty, got '$METRICS'" ;;
esac

# What state was the tree in when this was measured?
#
# `git diff --quiet` alone would call a tree with untracked files "clean", which
# is how a result ends up attributed to a commit that cannot reproduce it. The
# distinction that matters is whether TRACKED sources differ — those change the
# binary — so the two cases are reported separately rather than collapsed.
worktree_state() {
  local tracked untracked
  tracked=0
  ( cd "$SRC" && git diff --quiet && git diff --cached --quiet ) 2>/dev/null || tracked=1
  untracked="$( cd "$SRC" && git ls-files --others --exclude-standard 2>/dev/null | wc -l )"
  if [ "$tracked" = "1" ]; then
    echo "MODIFIED — tracked sources differ from the commit; this result is NOT reproducible from it"
  elif [ "${untracked:-0}" -gt 0 ]; then
    echo "tracked sources clean; ${untracked} untracked file(s) present (harness/docs — the binary matches the commit)"
  else
    echo "clean"
  fi
}

pin() {                                # $1 = cpu list, rest = command
  local cpus="$1"; shift
  if [ "$PIN" = "1" ] && command -v taskset >/dev/null 2>&1; then
    taskset -c "$cpus" "$@"
  else
    "$@"
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
SAMPLER_PID=""

stop_sampler() {
  [ -n "$SAMPLER_PID" ] || return 0
  kill "$SAMPLER_PID" 2>/dev/null || true
  wait "$SAMPLER_PID" 2>/dev/null || true
  SAMPLER_PID=""
}

# Pingora reads SIGTERM as *graceful* shutdown and lingers for its shutdown
# timeout; SIGINT is its fast path. Escalate if even that does not land.
stop_waf() {
  [ -n "$WAF_PID" ] || return 0
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
  stop_sampler
  if [ "$KEEP" = "1" ]; then
    log "KEEP=1 — leaving waf(pid=$WAF_PID) origin(pid=$BACKEND_PID) $PG_CONTAINER up"
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

# Pingora retries a busy listen socket forever instead of failing, so a
# stranger on $WAF_PORT would be silently benchmarked instead of the WAF.
port_busy() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
PORTS_TO_CHECK=("$WAF_PORT" "$WAF_TLS_PORT" "$API_PORT" "$BACKEND_PORT" "$METRICS_PORT")
[ "$SKIP_POSTGRES" = "1" ] || PORTS_TO_CHECK+=("$PG_PORT")
for p in "${PORTS_TO_CHECK[@]}"; do
  port_busy "$p" && die "port $p already in use — set WAF_PORT / API_PORT / BACKEND_PORT / PG_PORT"
done

command -v jq >/dev/null 2>&1 || die "jq is required"

# ── 1. Load generator + origin, both pinned ──────────────────────────────────
# oha: Rust, single static binary, `-j` emits machine-readable percentiles
# INCLUDING p99.9 — a WAF's failure mode is tail latency, and a tool that stops
# at p99 cannot show it. wrk needs a Lua script for POST bodies and reports no
# machine-readable tail; ab is single-threaded and HTTP/1.0.
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
OHA_BIN="${OHA_BIN:-}"
if [ -z "$OHA_BIN" ]; then
  if command -v oha >/dev/null 2>&1 &&
     [ "$(oha --version 2>/dev/null | awk '{print $2}')" = "$OHA_VERSION" ]; then
    OHA_BIN="$(command -v oha)"
  else
    log "installing oha $OHA_VERSION (this builds from source once)"
    cargo install oha --version "$OHA_VERSION" --locked --root "$WORK/cargo" >/dev/null
    OHA_BIN="$WORK/cargo/bin/oha"
  fi
fi
[ -x "$OHA_BIN" ] || die "oha not found: $OHA_BIN"

export GOPATH="$WORK/go" GOBIN="$WORK/bin"
mkdir -p "$GOBIN"
if [ ! -x "$GOBIN/albedo" ]; then
  command -v go >/dev/null 2>&1 || die "go toolchain required to install albedo"
  log "installing albedo@$ALBEDO_VERSION"
  go install "github.com/coreruleset/albedo@$ALBEDO_VERSION"
fi

# ── 2. prx-waf binary ────────────────────────────────────────────────────────
if [ -z "$PRXWAF_BIN" ]; then
  log "building prx-waf (release) from $SRC"
  ( cd "$SRC" && CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$SRC/target}" \
      cargo build --release -p prx-waf )
  PRXWAF_BIN="${CARGO_TARGET_DIR:-$SRC/target}/release/prx-waf"
fi
[ -x "$PRXWAF_BIN" ] || die "prx-waf binary not found: $PRXWAF_BIN"
[ -d "$SRC/rules/owasp-crs" ] || die "$SRC/rules/owasp-crs missing (rules load relative to CWD)"

# ── 3. Payloads ──────────────────────────────────────────────────────────────
# Generated, never committed: a 1 MiB fixture in git is noise, and generating it
# from a fixed recipe is what makes the workload reproducible, not the bytes.
PAY="$WORK/payloads"
mkdir -p "$PAY"

python3 - "$PAY" <<'PY'
import json, os, sys
out = sys.argv[1]

# A typical small API write: nested object, a handful of scalars, ~1 KiB.
api = {
    "user": {"id": 91823, "name": "Dana Whitfield", "email": "dana@example.com",
             "locale": "en-GB", "tz": "Europe/London"},
    "order": {"sku": "PRX-2291-B", "qty": 3, "currency": "GBP", "total": 149.97,
              "coupon": None, "notes": "leave with the concierge"},
    "address": {"line1": "18 Calderwood Street", "line2": "Flat 4B",
                "city": "London", "postcode": "SE18 6QP", "country": "GB"},
    "meta": {"client": "web", "version": "4.11.2", "session": "b2f4c1a9d7e" * 6},
}
body = json.dumps(api)
body += " " * max(0, 1024 - len(body))
with open(os.path.join(out, "json-post.json"), "w") as fh:
    fh.write(body)

# Form submission: the shape a login/checkout POST actually has.
form = ("username=dana.whitfield%40example.com&password=hunter2correcthorse"
        "&remember=1&csrf_token=" + "a3f9c1" * 20 +
        "&address_line1=18+Calderwood+Street&city=London&postcode=SE18+6QP")
form += "&filler=" + "x" * max(0, 512 - len(form) - 8)
with open(os.path.join(out, "form-post.txt"), "w") as fh:
    fh.write(form)

# A 1 MiB JSON body: exercises the buffer-then-scan window path, not the parser.
big = {"records": [{"id": i, "payload": "d7e3b9a1c5" * 8} for i in range(11000)]}
with open(os.path.join(out, "body-1mb.json"), "w") as fh:
    fh.write(json.dumps(big)[:1024 * 1024])

# 64 KiB multipart upload: two text fields plus a file part, so the part parser,
# the per-part header scan and the body processor all run.
B = "----prxwafperfboundary7f3a1c"
blob = ("PK\x03\x04" + "n7f3a1cd5" * 8000)[: 64 * 1024]
parts = [
    f"--{B}\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nquarterly report\r\n",
    f"--{B}\r\nContent-Disposition: form-data; name=\"visibility\"\r\n\r\ninternal\r\n",
    f"--{B}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"report.bin\"\r\n"
    f"Content-Type: application/octet-stream\r\n\r\n{blob}\r\n",
    f"--{B}--\r\n",
]
with open(os.path.join(out, "multipart.bin"), "w", newline="") as fh:
    fh.write("".join(parts))
with open(os.path.join(out, "multipart.boundary"), "w") as fh:
    fh.write(B)
PY

MULTIPART_BOUNDARY="$(cat "$PAY/multipart.boundary")"

# Every request carries a browser User-Agent, and that is load-bearing, not
# cosmetic: Lane 1's bot detector blocks `curl/*` outright (verified — a bare
# `curl http://waf/get?hello=world` gets 403 with `bot = true`). Benchmarking
# with a generator whose UA is blocked would measure the block page in the
# postures that have the bot detector on and the upstream hop in the ones that
# do not, i.e. it would compare two different code paths and call the
# difference "detection cost". A browser UA is also simply what benign traffic
# looks like.
UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

# workload → oha argument vector. `%URL%` is substituted with the base URL.
workload_args() {                      # $1 = workload name
  printf '%s\n' "-H" "User-Agent: $UA"
  case "$1" in
    get-small)
      printf '%s\n' "%URL%/get?q=hello&page=2&sort=created_at" ;;
    json-post)
      printf '%s\n' "-m" "POST" "-T" "application/json" \
                    "-D" "$PAY/json-post.json" "%URL%/post" ;;
    form-post)
      printf '%s\n' "-m" "POST" "-T" "application/x-www-form-urlencoded" \
                    "-D" "$PAY/form-post.txt" "%URL%/post" ;;
    multipart)
      printf '%s\n' "-m" "POST" \
                    "-T" "multipart/form-data; boundary=$MULTIPART_BOUNDARY" \
                    "-D" "$PAY/multipart.bin" "%URL%/post" ;;
    body-1mb)
      printf '%s\n' "-m" "POST" "-T" "application/json" \
                    "-D" "$PAY/body-1mb.json" "%URL%/post" ;;
    attack)
      # A payload every posture's detection is expected to have an opinion
      # about: union-select SQLi in a query parameter. Reported separately —
      # a blocked request never reaches the origin.
      printf '%s\n' "%URL%/get?id=1%27%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--" ;;
    *) die "unknown workload: $1" ;;
  esac
}

# ── 4. Postgres ──────────────────────────────────────────────────────────────
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
export JWT_SECRET="perf-harness-$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
export MASTER_KEY="perf-harness-$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
export ADMIN_PASSWORD="perf-harness-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"
export RUST_LOG="${RUST_LOG:-warn}"

# ── 5. Origin ────────────────────────────────────────────────────────────────
log "starting albedo origin on :$BACKEND_PORT (cpus $ORIGIN_CPUS)"
# `exec` inside the subshell, not the `pin` helper: backgrounding a shell
# FUNCTION makes `$!` the subshell's pid, and the resource sampler would then
# measure the wrapper (a few MiB, no CPU) instead of the origin.
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

# ── 6. Config generation ─────────────────────────────────────────────────────
# Every posture differs from `passthrough` by exactly the lines its case arm
# writes; everything else is byte-identical, so a delta cannot come from an
# incidental config difference.
gen_config() {                         # $1 = posture, $2 = output path
  local posture="$1" dst="$2"
  local bot=false sqli=false xss=false scan=false rce=false sensitive=false
  local traversal=false owasp=false cc=false pl=1 cs_enabled=false metrics_enabled=true

  case "$posture" in
    passthrough) ;;
    lane1) bot=true sqli=true xss=true scan=true rce=true sensitive=true traversal=true ;;
    # Single-detector postures, for bisecting Lane 1 when the aggregate looks
    # wrong. Each turns on exactly one native detector over `passthrough`.
    lane1-bot)       bot=true ;;
    lane1-sqli)      sqli=true ;;
    lane1-xss)       xss=true ;;
    lane1-scan)      scan=true ;;
    lane1-rce)       rce=true ;;
    lane1-sensitive) sensitive=true ;;
    lane1-traversal) traversal=true ;;
    crs-pl1) owasp=true pl=1 ;;
    crs-pl2) owasp=true pl=2 ;;
    crs-pl4) owasp=true pl=4 ;;
    lane2) cs_enabled=true ;;
    cc)    cc=true ;;
    full)  bot=true sqli=true xss=true scan=true rce=true sensitive=true traversal=true
           owasp=true pl=1 cc=true cs_enabled=true ;;
    # The metrics A/B. Identical detection to the posture it names, with
    # recording off — so the delta is the recording and nothing else.
    passthrough-nometrics) metrics_enabled=false ;;
    full-nometrics)
           bot=true sqli=true xss=true scan=true rce=true sensitive=true traversal=true
           owasp=true pl=1 cc=true cs_enabled=true metrics_enabled=false ;;
    *) die "unknown posture: $posture" ;;
  esac

  # The global knob overrides the posture, so METRICS=0 measures every posture
  # with recording off without needing a `-nometrics` twin for each one.
  [ "$METRICS" = "0" ] && metrics_enabled=false
  [ "$METRICS" = "1" ] && metrics_enabled=true

  {
    cat <<EOF
# Generated by tests/perf/run.sh — do not edit, do not commit.
# Posture: $posture
[proxy]
listen_addr = "127.0.0.1:$WAF_PORT"
listen_addr_tls = "127.0.0.1:$WAF_TLS_PORT"
trust_proxy_headers = false
smuggling_detection = true
$([ -n "$WORKER_THREADS" ] && printf 'worker_threads = %s' "$WORKER_THREADS")

[api]
listen_addr = "127.0.0.1:$API_PORT"

# Written explicitly in every posture, never left to the default, so the config
# file left behind in \$WORK states which side of the metrics question the run
# was on. \`enabled = false\` is what the \`*-nometrics\` postures select.
[metrics]
enabled = $metrics_enabled
listen_addr = "127.0.0.1:$METRICS_PORT"

[storage]
database_url = "$DATABASE_URL"
max_connections = 20

# Response caching OFF in every posture, including \`full\`. A cache hit skips
# the upstream entirely and would make the WAF measure FASTER than the origin
# it fronts, drowning every detection delta this harness exists to isolate.
[cache]
enabled = false
max_size_mb = 1
default_ttl_secs = 0
max_ttl_secs = 0

# GeoIP off: the xdb databases are not shipped, so leaving it on would measure
# a lookup that silently no-ops — a zero with a misleading name on it.
[geoip]
enabled = false

[rules]
dir = "rules/"
hot_reload = false
enable_builtin_owasp = $owasp
enable_builtin_bot = $bot
enable_builtin_scanner = $scan

# Exact host:port key — the router only falls back to a bare hostname on ports
# 80/443 (gateway/src/router.rs, \`resolve\`), and the generator sends
# \`Host: 127.0.0.1:$WAF_PORT\`.
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
      # The rate limiter must not actually fire: this measures the cost of the
      # token-bucket lookup on every request, not the cost of being banned.
      # A benched limiter that starts returning 429 measures nothing useful.
      cat <<'EOF'
cc_rps = 1000000.0
cc_burst = 2000000
cc_ban_threshold = 4294967295
EOF
    fi

    if [ "$cs_enabled" = "true" ]; then
      # The Lane 2 block is lifted verbatim out of configs/default.toml rather
      # than retyped, so the measured posture is the SHIPPING posture
      # (log_only + rollout_bps = 0) and cannot drift from it.
      #
      # LANE1_MAX_BODY_BYTES rewrites the one key it names in place. Appending a
      # second `[content_security.lane1]` table would be a duplicate-key TOML
      # error, and appending a bare `max_body_bytes` would land in whichever
      # table happens to be last in the shipped file.
      echo
      if [ -n "$LANE1_MAX_BODY_BYTES" ]; then
        sed -n '/^\[content_security\]/,$p' "$SRC/configs/default.toml" |
          sed "s/^max_body_bytes = .*/max_body_bytes = $LANE1_MAX_BODY_BYTES  # overridden by tests\/perf\/run.sh/"
      else
        sed -n '/^\[content_security\]/,$p' "$SRC/configs/default.toml"
      fi
    else
      # Lane 2 off. The Lane 1 body budget still applies here — it is compiled
      # out of `[content_security.lane1]` whatever `enabled` says, because it
      # governs the four legacy regex detectors and not the semantic lane — so
      # the override has to be written on this branch too, or the `lane1` and
      # `crs-*` postures would silently keep the shipped 64 KiB.
      cat <<'EOF'

[content_security]
enabled = false
EOF
      if [ -n "$LANE1_MAX_BODY_BYTES" ]; then
        printf '\n[content_security.lane1]\nmax_body_bytes = %s\n' "$LANE1_MAX_BODY_BYTES"
      fi
    fi
  } >"$dst"
}

# ── 7. Resource sampling ─────────────────────────────────────────────────────
# CPU comes from /proc/<pid>/stat utime+stime deltas across the measured window
# and is reported in cores, not percent: "0.94 cores" says immediately whether
# a single-threaded service is saturated, "94%" does not say of what.
clk_tck="$(getconf CLK_TCK)"

cpu_ticks() {                          # $1 = pid → utime+stime in ticks
  awk '{ n = split($0, f, ") "); split(f[n], g, " "); print g[12] + g[13] }' \
    "/proc/$1/stat" 2>/dev/null || echo 0
}

thread_count() { ls "/proc/$1/task" 2>/dev/null | wc -l; }

RSS_FILE="$WORK/.rss"
start_sampler() {                      # $1 = pid
  : >"$RSS_FILE"
  (
    max=0
    while :; do
      cur="$(awk '/^VmRSS:/{print $2}' "/proc/$1/status" 2>/dev/null || true)"
      if [ -n "${cur:-}" ] && [ "$cur" -gt "$max" ]; then
        max="$cur"
        printf '%s\n' "$max" >"$RSS_FILE"
      fi
      sleep 0.2
    done
  ) &
  SAMPLER_PID=$!
}

# ── 8. One measured round ────────────────────────────────────────────────────
RESULTS="$OUT/raw.jsonl"
: >"$RESULTS"

run_round() {                          # $1 posture, $2 workload, $3 round, $4 base url, $5 pid|""
  local posture="$1" workload="$2" round="$3" base="$4" subject_pid="$5"
  local args=() a
  while IFS= read -r a; do args+=("${a//%URL%/$base}"); done < <(workload_args "$workload")

  local jsonf="$OUT/$posture.$workload.r$round.json"
  local cpu_before=0 cpu_after=0 rss_kb=0 threads=0
  [ -n "$subject_pid" ] && cpu_before="$(cpu_ticks "$subject_pid")"
  [ -n "$subject_pid" ] && start_sampler "$subject_pid"

  local t0 t1 elapsed
  t0="$(date +%s.%N)"
  pin "$LOAD_CPUS" "$OHA_BIN" --no-tui --output-format json \
      -c "$CONNECTIONS" -z "${DURATION}s" \
      "${args[@]}" >"$jsonf" 2>"$jsonf.err" || {
        cat "$jsonf.err" >&2; die "oha failed for $posture/$workload"; }
  t1="$(date +%s.%N)"
  elapsed="$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.4f", b-a}')"

  if [ -n "$subject_pid" ]; then
    cpu_after="$(cpu_ticks "$subject_pid")"
    threads="$(thread_count "$subject_pid")"
    stop_sampler
    rss_kb="$(cat "$RSS_FILE" 2>/dev/null || echo 0)"
  fi
  local cores
  cores="$(awk -v d="$((cpu_after - cpu_before))" -v t="$clk_tck" -v e="$elapsed" \
              'BEGIN{ if (e > 0 && t > 0) printf "%.3f", (d/t)/e; else print "0" }')"

  jq -c --arg posture "$posture" --arg workload "$workload" --argjson round "$round" \
        --argjson cores "$cores" --argjson rss_kb "${rss_kb:-0}" \
        --argjson threads "${threads:-0}" --argjson elapsed "$elapsed" '
    {
      posture: $posture, workload: $workload, round: $round,
      rps:      (.summary.requestsPerSec),
      success:  (.summary.successRate),
      # `summary.total` is the elapsed WALL TIME in seconds, not a request
      # count — the request count only exists as the status-code histogram.
      requests: ([.statusCodeDistribution[]] | add // 0),
      p50:      (.latencyPercentiles."p50"),
      p95:      (.latencyPercentiles."p95"),
      p99:      (.latencyPercentiles."p99"),
      p999:     (.latencyPercentiles."p99.9"),
      max:      (.summary.slowest),
      status:   (.statusCodeDistribution),
      errors:   (.errorDistribution),
      cpu_cores: $cores, rss_kb: $rss_kb, threads: $threads, elapsed_s: $elapsed
    }' "$jsonf" >>"$RESULTS"

  local rps p99 codes
  rps="$(jq -r '.summary.requestsPerSec | floor' "$jsonf")"
  p99="$(jq -r '(.latencyPercentiles."p99" * 1000) | floor' "$jsonf")"
  codes="$(jq -r '.statusCodeDistribution | to_entries | map("\(.key):\(.value)") | join(" ")' "$jsonf")"
  log "    r$round  rps=$rps  p99=${p99}ms  cpu=${cores}c  rss=$((rss_kb / 1024))MiB  [$codes]"

  # A benign workload that is being blocked is not measuring what its name
  # says: a 403 short-circuits before the upstream, so the row would be faster
  # than the honest number and the comparison would be silently invalid.
  if [ "$workload" != "attack" ]; then
    local non200
    non200="$(jq -r '[.statusCodeDistribution | to_entries[] | select(.key != "200") | .value] | add // 0' "$jsonf")"
    if [ "${non200:-0}" -gt 0 ]; then
      log "    !! $posture/$workload: $non200 non-200 responses — this row does NOT measure the proxied path"
    fi
  fi
}

# ── 9. Drive every posture ───────────────────────────────────────────────────
log "hardware: $(nproc) cpus, $(awk '/^model name/{sub(/^model name[ \t]*:[ \t]*/,""); print; exit}' /proc/cpuinfo)"
log "kernel:   $(uname -r)"
log "plan:     postures=[$POSTURES] workloads=[$WORKLOADS] rounds=$ROUNDS duration=${DURATION}s conns=$CONNECTIONS pin=$PIN"
log "pinning:  waf=$WAF_CPUS origin=$ORIGIN_CPUS generator=$LOAD_CPUS"
log "config:   worker_threads=${WORKER_THREADS:-<shipped default: the CPUs the process may use>} lane1.max_body_bytes=${LANE1_MAX_BODY_BYTES:-<shipped default: 65536>}"

# The 1-minute load average at the start and end of the run. A benchmark host
# that was busy with unrelated work produces numbers that are real but not
# repeatable, and the reader has to be told which one they are holding. This is
# recorded rather than asserted on: refusing to run on a busy host would just
# mean no measurement at all.
LOAD_BEFORE="$(awk '{print $1}' /proc/loadavg)"

MIGRATED=0
IFS=',' read -ra POSTURE_LIST <<<"$POSTURES"
IFS=',' read -ra WORKLOAD_LIST <<<"$WORKLOADS"

for posture in "${POSTURE_LIST[@]}"; do
  base=""
  subject_pid=""

  if [ "$posture" = "origin" ]; then
    log "posture: origin — generator straight at albedo, no proxy in path"
    base="http://127.0.0.1:$BACKEND_PORT"
    subject_pid="$BACKEND_PID"
  else
    cfg="$WORK/prx-waf-$posture.toml"
    waflog="$WORK/prx-waf-$posture.log"
    gen_config "$posture" "$cfg"

    if [ "$MIGRATED" = "0" ]; then
      log "migrating database"
      ( cd "$SRC" && "$PRXWAF_BIN" --config "$cfg" migrate ) >"$WORK/migrate.log" 2>&1 \
        || die "migration failed, see $WORK/migrate.log"
      MIGRATED=1
    fi

    log "posture: $posture — starting prx-waf on :$WAF_PORT (cpus $WAF_CPUS)"
    (
      cd "$SRC"
      if [ "$PIN" = "1" ] && command -v taskset >/dev/null 2>&1; then
        exec taskset -c "$WAF_CPUS" "$PRXWAF_BIN" --config "$cfg" run
      else
        exec "$PRXWAF_BIN" --config "$cfg" run
      fi
    ) >"$waflog" 2>&1 &
    WAF_PID=$!
    ready=0
    for _ in $(seq 1 90); do
      if curl -s -o /dev/null "http://127.0.0.1:$WAF_PORT/get"; then ready=1; break; fi
      kill -0 "$WAF_PID" 2>/dev/null || break
      sleep 0.5
    done
    [ "$ready" = "1" ] || { tail -40 "$waflog" >&2; die "prx-waf did not come up (see $waflog)"; }

    # Sanity gate. A posture that is silently not doing its job would report a
    # flattering number, and a flattering number is the failure mode this whole
    # exercise exists to avoid. Benign must pass; the attack payload must be
    # blocked by every posture that claims a detector, and must NOT be blocked
    # by passthrough (which would mean detection is on when it should be off).
    # -A: curl's own UA is blocked by the bot detector, so a bare probe would
    # report 403 for the wrong reason and abort a perfectly good run.
    benign="$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" \
      "http://127.0.0.1:$WAF_PORT/get?hello=world")"
    attack="$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" \
      "http://127.0.0.1:$WAF_PORT/get?id=1%27%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--")"
    log "  sanity: benign=$benign attack=$attack"
    [ "$benign" = "200" ] || die "sanity: benign request returned $benign, expected 200"
    case "$posture" in
      passthrough|cc)
        [ "$attack" != "403" ] || die "sanity: $posture blocked a SQLi payload — detection is ON when it should be OFF" ;;
      lane1|lane1-sqli|crs-pl1|crs-pl2|crs-pl4|full)
        [ "$attack" = "403" ] || die "sanity: $posture returned $attack for a SQLi payload, expected 403 — the layer under test is not doing anything" ;;
      lane1-*)
        # A single non-SQLi detector is not expected to have an opinion about a
        # SQLi payload, so there is nothing to assert here beyond the benign
        # check above. Listed explicitly so the case is a decision, not a gap.
        : ;;
      lane2)
        # Shipping Lane 2 posture is shadow (log_only + rollout_bps = 0): it is
        # SUPPOSED to observe and not block. A 403 here would mean the measured
        # posture is not the shipping one.
        [ "$attack" != "403" ] || die "sanity: lane2 blocked — expected shadow posture (log_only, rollout_bps=0)" ;;
    esac

    base="http://127.0.0.1:$WAF_PORT"
    subject_pid="$WAF_PID"
  fi

  for workload in "${WORKLOAD_LIST[@]}"; do
    log "  $posture / $workload  (warmup ${WARMUP}s)"
    wargs=(); while IFS= read -r a; do wargs+=("${a//%URL%/$base}"); done < <(workload_args "$workload")
    pin "$LOAD_CPUS" "$OHA_BIN" --no-tui --output-format json \
      -c "$CONNECTIONS" -z "${WARMUP}s" "${wargs[@]}" >/dev/null 2>&1 || true
    for r in $(seq 1 "$ROUNDS"); do
      run_round "$posture" "$workload" "$r" "$base" "$subject_pid"
    done
  done

  [ "$posture" = "origin" ] || stop_waf
done

# ── 10. Aggregate ────────────────────────────────────────────────────────────
log "aggregating → $OUT/summary.json"
python3 "$SCRIPT_DIR/summarize.py" \
  --raw "$RESULTS" --out "$OUT/summary.json" --markdown "$OUT/summary.md" \
  --duration "$DURATION" --connections "$CONNECTIONS" --rounds "$ROUNDS" \
  --oha "$OHA_VERSION" --albedo "$ALBEDO_VERSION" --pin "$PIN" \
  --waf-cpus "$WAF_CPUS" --origin-cpus "$ORIGIN_CPUS" --load-cpus "$LOAD_CPUS" \
  --worker-threads "$WORKER_THREADS" --lane1-max-body-bytes "$LANE1_MAX_BODY_BYTES" \
  --load-before "$LOAD_BEFORE" --load-after "$(awk '{print $1}' /proc/loadavg)" \
  --tree "$(cd "$SRC" && git rev-parse HEAD 2>/dev/null || echo unknown)" \
  --dirty "$(worktree_state)"

cat "$OUT/summary.md"
log "raw records: $RESULTS"
log "summary:     $OUT/summary.json  $OUT/summary.md"
