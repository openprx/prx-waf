#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# OWASP CRS official regression suite (go-ftw) against prx-waf.
#
#   tests/ftw/run.sh                    # log mode, paranoia level 1
#   MODE=cloud tests/ftw/run.sh         # cloud mode (status codes only)
#   PL=2 tests/ftw/run.sh               # paranoia level 2
#   PL=1,2,4 tests/ftw/run.sh           # several levels in one go
#
# Brings up everything it needs, runs the suite, prints a classified report and
# tears the environment down again. Nothing is left running and nothing is
# written outside $WORK (default: a directory under $TMPDIR) except the report
# files, which land in $OUT (default: $WORK/reports).
#
# ── How the verdict is reached: two modes, two questions ─────────────────────
# go-ftw has two ways to decide whether a rule fired, and they do not ask the
# same question of the WAF. Both are supported; `MODE` selects one.
#
# MODE=log (default) — what upstream measures
#   The corpus is read as written: each test asserts that specific rule ids do
#   (`expect_ids`) or do not (`no_expect_ids`) appear in the WAF's log, and
#   go-ftw brackets each stage between two `X-CRS-Test` marker requests so it
#   reads only that stage's lines (go-ftw runner/run.go `markAndFlush`,
#   waflog/read.go `getMarkedLines`). The WAF runs in DetectionOnly
#   (`log_only_mode = true`): nothing is blocked, and the verdict comes from
#   prx-waf's rule-hit audit log, which this harness switches on. This is the
#   posture ModSecurity v2 + CRS and Coraza are measured in, so it is the number
#   that is comparable to their 100%.
#
# MODE=cloud — what a user experiences
#   go-ftw never reads a log; it only looks at the HTTP status code. A test that
#   expects a rule to fire passes iff the response is 403; a test that expects no
#   rule to fire passes iff the response is 200, 404 or 405 (go-ftw
#   check/status.go, `negativeExpectedStatuses`). The WAF blocks normally.
#
#   The two numbers are NOT interchangeable, and cloud mode is the harsher of
#   the two by construction: a negative test asserts "rule X must not fire", but
#   a status code can only express "nothing at all blocked", so any other CRS
#   rule blocking the request fails the test even though upstream would have
#   logged that rule and moved on. Quote the mode with every figure.
#
# ── What is measured ─────────────────────────────────────────────────────────
# The CRS check only. Every prx-waf-native Lane 1 detector (sqli/xss/rce/…) and
# the Lane 2 semantic engine are switched OFF for the run, so a pass can only
# come from a CRS rule and a false positive can only come from a CRS rule. That
# is what makes the number comparable to ModSecurity+CRS or Coraza+CRS.
# Rate limiting (`cc`) is also off: go-ftw fires ~4.7k requests from one IP in
# cloud mode and ~14k in log mode (two marker requests per stage).
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"

# ── Pins. Everything that can drift is pinned; change deliberately. ──────────
CRS_VERSION="${CRS_VERSION:-v4.25.0}"        # must match rules/owasp-crs/README.md
GO_FTW_VERSION="${GO_FTW_VERSION:-v1.3.0}"
ALBEDO_VERSION="${ALBEDO_VERSION:-v0.3.0}"
POSTGRES_IMAGE="${POSTGRES_IMAGE:-docker.io/library/postgres:16}"

# ── Knobs ────────────────────────────────────────────────────────────────────
MODE="${MODE:-log}"                           # log | cloud — see the header
PL="${PL:-1}"                                 # comma-separated paranoia levels
WORK="${WORK:-${TMPDIR:-/tmp}/prx-waf-ftw}"
OUT="${OUT:-$WORK/reports}"
SRC="${SRC:-$REPO_ROOT}"                      # tree to build and to load rules from
PRXWAF_BIN="${PRXWAF_BIN:-}"                  # skip the build by supplying a binary
WAF_PORT="${WAF_PORT:-18901}"
WAF_TLS_PORT="${WAF_TLS_PORT:-18944}"
API_PORT="${API_PORT:-19911}"
BACKEND_PORT="${BACKEND_PORT:-18988}"
PG_PORT="${PG_PORT:-15433}"
PG_CONTAINER="${PG_CONTAINER:-prx-waf-ftw-pg}"
KEEP="${KEEP:-0}"                             # KEEP=1 leaves the environment up
FTW_ARGS="${FTW_ARGS:-}"                      # extra flags passed through to go-ftw
APPLY_EXCLUSIONS="${APPLY_EXCLUSIONS:-0}"     # 1 => also emit the exclusion-scoped number
SKIP_POSTGRES="${SKIP_POSTGRES:-0}"           # 1 => a Postgres is already listening on $PG_PORT
REPLAY="${REPLAY:-0}"                         # 1 => re-send failures to record status + rule
BASELINE="${BASELINE:-}"                      # baseline json; non-empty makes the run gate

CONTAINER_CLI="${CONTAINER_CLI:-}"
if [ -z "$CONTAINER_CLI" ]; then
  if command -v podman >/dev/null 2>&1; then CONTAINER_CLI=podman
  elif command -v docker >/dev/null 2>&1; then CONTAINER_CLI=docker
  else echo "need podman or docker" >&2; exit 1; fi
fi

log() { printf '\033[1;36m[ftw]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31m[ftw] %s\033[0m\n' "$*" >&2; exit 1; }

case "$MODE" in
  log|cloud) ;;
  *) die "MODE must be 'log' or 'cloud', got '$MODE'" ;;
esac

# Pingora treats SIGTERM as *graceful* shutdown and keeps the process alive for
# its shutdown timeout, so a plain `kill; wait` hangs the harness between
# paranoia levels. SIGINT is Pingora's fast shutdown; escalate to SIGKILL if
# even that does not land within a few seconds.
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

# ── Teardown ─────────────────────────────────────────────────────────────────
WAF_PID=""
BACKEND_PID=""
teardown() {
  local rc=$?
  if [ "$KEEP" = "1" ]; then
    log "KEEP=1 — leaving waf(pid=$WAF_PID) backend(pid=$BACKEND_PID) $PG_CONTAINER up"
    return $rc
  fi
  stop_waf
  [ -n "$BACKEND_PID" ] && kill "$BACKEND_PID" 2>/dev/null || true
  sleep 0.5
  [ -n "$BACKEND_PID" ] && kill -9 "$BACKEND_PID" 2>/dev/null || true
  [ "$SKIP_POSTGRES" = "1" ] || "$CONTAINER_CLI" rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true
  return $rc
}
trap teardown EXIT

mkdir -p "$WORK" "$OUT"

# Pingora retries a busy listen socket forever instead of failing, and a
# stranger answering on $WAF_PORT would be silently measured instead of the WAF.
port_busy() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
PORTS_TO_CHECK=("$WAF_PORT" "$WAF_TLS_PORT" "$API_PORT" "$BACKEND_PORT")
[ "$SKIP_POSTGRES" = "1" ] || PORTS_TO_CHECK+=("$PG_PORT")
for p in "${PORTS_TO_CHECK[@]}"; do
  if port_busy "$p"; then
    die "port $p is already in use — set WAF_PORT / WAF_TLS_PORT / API_PORT / BACKEND_PORT / PG_PORT"
  fi
done

# ── 1. go-ftw + albedo ───────────────────────────────────────────────────────
export GOPATH="$WORK/go" GOBIN="$WORK/bin"
mkdir -p "$GOBIN"
if [ ! -x "$GOBIN/go-ftw" ]; then
  command -v go >/dev/null 2>&1 || die "go toolchain required to install go-ftw"
  log "installing go-ftw@$GO_FTW_VERSION"
  go install "github.com/coreruleset/go-ftw@$GO_FTW_VERSION"
fi
if [ ! -x "$GOBIN/albedo" ]; then
  log "installing albedo@$ALBEDO_VERSION"
  go install "github.com/coreruleset/albedo@$ALBEDO_VERSION"
fi

# ── 2. CRS corpus at the pinned tag ──────────────────────────────────────────
CRS_DIR="$WORK/coreruleset-$CRS_VERSION"
if [ ! -d "$CRS_DIR/tests/regression/tests" ]; then
  log "cloning coreruleset $CRS_VERSION"
  rm -rf "$CRS_DIR"
  git clone --quiet --depth 1 --branch "$CRS_VERSION" \
    https://github.com/coreruleset/coreruleset.git "$CRS_DIR"
fi

# ── 3. prx-waf binary ────────────────────────────────────────────────────────
if [ -z "$PRXWAF_BIN" ]; then
  log "building prx-waf (release) from $SRC"
  ( cd "$SRC" && CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$SRC/target}" \
      cargo build --release -p prx-waf )
  PRXWAF_BIN="${CARGO_TARGET_DIR:-$SRC/target}/release/prx-waf"
fi
[ -x "$PRXWAF_BIN" ] || die "prx-waf binary not found: $PRXWAF_BIN"
[ -d "$SRC/rules/owasp-crs" ] || die "$SRC/rules/owasp-crs missing (rules are loaded relative to CWD)"

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

# Reset the schema between paranoia levels. Uses psql in the container when we
# own it, and the DATABASE_URL otherwise.
reset_schema() {
  if [ "$SKIP_POSTGRES" = "1" ]; then
    command -v psql >/dev/null 2>&1 &&
      psql "$DATABASE_URL" -q -c 'DROP SCHEMA public CASCADE; CREATE SCHEMA public;' >/dev/null 2>&1 || true
  else
    "$CONTAINER_CLI" exec "$PG_CONTAINER" psql -U prx_waf -d prx_waf -q \
      -c 'DROP SCHEMA public CASCADE; CREATE SCHEMA public;' >/dev/null 2>&1 || true
  fi
}

# ── 5. Backend (albedo — the same reflector CRS uses upstream) ────────────────
log "starting albedo backend on :$BACKEND_PORT"
"$GOBIN/albedo" --bind 127.0.0.1 --port "$BACKEND_PORT" >"$WORK/albedo.log" 2>&1 &
BACKEND_PID=$!
for _ in $(seq 1 30); do
  curl -sf "http://127.0.0.1:$BACKEND_PORT/capabilities" >/dev/null 2>&1 && break
  sleep 0.3
done

export DATABASE_URL="postgresql://prx_waf:prx_waf@127.0.0.1:$PG_PORT/prx_waf"
export JWT_SECRET="ftw-harness-$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
export MASTER_KEY="ftw-harness-$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
export ADMIN_PASSWORD="ftw-harness-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"
export RUST_LOG="${RUST_LOG:-warn}"

# ── Config generation ────────────────────────────────────────────────────────
gen_config() {                      # $1 = paranoia level, $2 = output path, $3 = audit log path
  local pl="$1" dst="$2" auditlog="$3"
  local log_only=false
  # go-ftw's log mode reads the corpus as written, and the corpus was written
  # against `SecRuleEngine DetectionOnly`. Its negative tests assert "rule X did
  # not fire", not "the request was not blocked" — so a WAF that blocks fails
  # them for the wrong reason, and its positive tests never see a rule logged
  # after the first block short-circuits the pipeline. DetectionOnly is not a
  # concession to the harness; it is the posture the reference numbers were
  # measured in.
  [ "$MODE" = "log" ] && log_only=true
  {
    cat <<EOF
# Generated by tests/ftw/run.sh — do not edit, do not commit.
# CRS regression harness, paranoia level $pl, $MODE mode.
[proxy]
listen_addr = "127.0.0.1:$WAF_PORT"
listen_addr_tls = "127.0.0.1:$WAF_TLS_PORT"
trust_proxy_headers = false
smuggling_detection = true

[api]
listen_addr = "127.0.0.1:$API_PORT"

# Off. These harnesses measure detection, and a scrape endpoint is a
# host-global port (the default is 127.0.0.1:9090) that a second harness, or the
# machine's own Prometheus, would be fighting for. A failed bind is only logged,
# so leaving it on would not break a run — it would just put an unexplained
# ERROR in every waf log for the next person to read.
[metrics]
enabled = false

[storage]
database_url = "$DATABASE_URL"
max_connections = 5

# Response caching off: a cached 200 would mask a later block decision.
[cache]
enabled = false
max_size_mb = 1
default_ttl_secs = 0
max_ttl_secs = 0

[rules]
dir = "rules/"
hot_reload = false
enable_builtin_owasp = true
enable_builtin_bot = false
enable_builtin_scanner = false
EOF

    if [ "$MODE" = "log" ]; then
      cat <<EOF

# The rule-hit audit log is what go-ftw's log mode reads. Rotation is off for
# the duration of the run: go-ftw holds one open file descriptor for the whole
# suite (waflog/waflog.go, openLogFile) and would follow a rotated-away inode.
# marker_header makes a request carrying X-CRS-Test log only that marker, which
# is what upstream's rule 999999 + ctl:ruleRemoveById=1-999999 does.
[audit_log]
enabled = true
path = "$auditlog"
max_size_mb = 0
keep_rotations = 0
include_query = false
marker_header = "X-CRS-Test"
EOF
    fi
    grep -v -e '^[[:space:]]*#' -e '^[[:space:]]*$' "$SCRIPT_DIR/hosts.txt" | while IFS= read -r entry; do
      local name port
      case "$entry" in
        # The 920280 tests send an empty Host on purpose; without a route the
        # gateway 404s them before any rule can be evaluated.
        '<empty>') name=""; port=80 ;;
        # bracketed IPv6 with explicit port, e.g. [fe80::1]:80
        \[*\]:*) name="${entry%:*}"; port="${entry##*:}" ;;
        \[*\])   name="$entry";     port=80 ;;
        *:*)     name="${entry%:*}"; port="${entry##*:}" ;;
        *)       name="$entry";     port=80 ;;
      esac
      cat <<EOF

[[hosts]]
host = "$name"
port = $port
remote_host = "127.0.0.1"
remote_port = $BACKEND_PORT
guard_status = true
# DetectionOnly in log mode, enforce in cloud mode — see gen_config.
log_only_mode = $log_only
[hosts.defense_config]
# Every prx-waf-native Lane 1 detector is off: this run measures the CRS
# check and nothing else, so the number is comparable to ModSecurity+CRS.
bot = false
sqli = false
xss = false
scan = false
rce = false
sensitive = false
dir_traversal = false
owasp_set = true
# Rate limiting off — go-ftw sends ~4.7k requests from a single source IP.
cc = false
owasp_paranoia = $pl
EOF
    done
  } >"$dst"
}

# ── go-ftw config ────────────────────────────────────────────────────────────
# `logfile` and `mode` are per-paranoia-level in log mode (one audit log per
# level), so the file is written inside run_pl.
gen_ftw_conf() {                    # $1 = output path, $2 = audit log path, $3 = 1 => force-fail the retry_once tests
  local dst="$1" auditlog="$2" quarantine="${3:-0}"
  {
    if [ "$MODE" = "cloud" ]; then
      cat <<EOF
# Generated by tests/ftw/run.sh.
# cloud mode: verdicts come from HTTP status codes only, never from WAF logs.
mode: cloud
EOF
    else
      cat <<EOF
# Generated by tests/ftw/run.sh.
# log mode (go-ftw calls it the *default* mode): verdicts come from the rule ids
# prx-waf wrote to its audit log between this stage's two X-CRS-Test markers.
mode: default
logfile: "$auditlog"
logmarkerheadername: "X-CRS-Test"
EOF
    fi
    cat <<EOF
testoverride:
  input:
    dest_addr: "127.0.0.1"
    port: $WAF_PORT
EOF
    if [ "$quarantine" = "1" ] && [ -n "$RETRY_ONCE_RE" ]; then
      cat <<EOF
  # go-ftw aborts the ENTIRE run — no results file, no exit summary — when a test
  # marked \`retry_once\` fails twice: runner/run.go RunTest retries once and then
  # propagates the "retry-once" error up through Run(). A WAF that fails such a
  # test therefore gets no number at all. These are quarantined out of the bulk
  # run and each is re-run on its own below, so one of them cannot take the other
  # 4669 with it. \`forcefail\` (not \`ignore\`/\`forcepass\`) keeps them counted.
  forcefail:
    '$RETRY_ONCE_RE': 'quarantined: go-ftw aborts the whole run if a retry_once test fails twice; re-run individually'
EOF
    fi
  } >"$dst"
}

# ── The `retry_once` quarantine list, read from the corpus ───────────────────
# Derived, not hard-coded: a CRS bump that marks another test `retry_once` must
# not silently reintroduce the abort.
RETRY_ONCE_IDS="$(python3 - "$CRS_DIR" <<'PY'
import glob, os, sys, yaml
root = os.path.join(sys.argv[1], "tests", "regression", "tests")
for path in sorted(glob.glob(os.path.join(root, "**", "*.yaml"), recursive=True)):
    with open(path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    if not isinstance(doc, dict) or "tests" not in doc:
        continue
    for case in doc.get("tests") or []:
        if any((s.get("output") or {}).get("retry_once") for s in case.get("stages") or []):
            print(f"{doc.get('rule_id')}-{case['test_id']}")
PY
)"
RETRY_ONCE_RE=""
if [ -n "$RETRY_ONCE_IDS" ]; then
  RETRY_ONCE_RE="^($(echo "$RETRY_ONCE_IDS" | tr '\n' '|' | sed 's/|$//'))\$"
fi
log "retry_once quarantine: $(echo "$RETRY_ONCE_IDS" | tr '\n' ' ')"

# The CRS corpus asserts on ModSecurity's DetectionOnly audit log and carries
# almost no `output.status`. go-ftw's cloud mode returns *true* whenever a test
# has no status expectation (check/status.go: `if c.expected.Status == 0`), so
# without this file a cloud run asserts nothing and reports ~100%. The generator
# restates each existing log assertion as its blocking-mode status code and
# changes nothing else — see the header of gen_overrides.py.
#
# Log mode needs none of it: it reads the log assertions the corpus already
# carries, which is the whole point of running the corpus as written.
BLOCKING_OVERRIDES="$WORK/blocking-mode-overrides.yaml"
if [ "$MODE" = "cloud" ]; then
  log "generating blocking-mode status expectations"
  python3 "$SCRIPT_DIR/gen_overrides.py" --crs "$CRS_DIR" --out "$BLOCKING_OVERRIDES"
fi

# ── Run one paranoia level ───────────────────────────────────────────────────
run_pl() {
  local pl="$1"
  local cfg="$WORK/prx-waf-pl$pl.toml"
  local waflog="$WORK/prx-waf-pl$pl.log"
  local auditlog="$WORK/audit-pl$pl.log"
  local ftw_conf="$WORK/.ftw-pl$pl.yaml"
  local results="$OUT/results-pl$pl.json"

  gen_config "$pl" "$cfg" "$auditlog"
  gen_ftw_conf "$ftw_conf" "$auditlog" 1
  gen_ftw_conf "$WORK/.ftw-solo-pl$pl.yaml" "$auditlog" 0
  # A stale audit log from a previous level would put another level's rule hits
  # before this run's first marker. go-ftw also `os.Open`s the file up front and
  # aborts if it is missing (waflog/waflog.go), so it has to exist before the
  # WAF has written anything.
  rm -f "$auditlog"
  : >"$auditlog"

  log "PL$pl: migrating database"
  ( cd "$SRC" && "$PRXWAF_BIN" --config "$cfg" migrate ) >"$WORK/migrate-pl$pl.log" 2>&1 \
    || die "migration failed, see $WORK/migrate-pl$pl.log"

  log "PL$pl: starting prx-waf on :$WAF_PORT"
  ( cd "$SRC" && exec "$PRXWAF_BIN" --config "$cfg" run ) >"$waflog" 2>&1 &
  WAF_PID=$!
  local ready=0
  for _ in $(seq 1 60); do
    if curl -s -o /dev/null -H 'Host: localhost' "http://127.0.0.1:$WAF_PORT/get"; then
      ready=1; break
    fi
    kill -0 "$WAF_PID" 2>/dev/null || break
    sleep 0.5
  done
  [ "$ready" = "1" ] || { tail -40 "$waflog" >&2; die "prx-waf did not come up (see $waflog)"; }

  # Sanity gate: the harness is worthless if the WAF is not doing what the mode
  # assumes. Fail loudly rather than reporting a 0% (or a 100%) that is really a
  # wiring bug. What "working" means differs by mode, so the gate does too.
  local benign attack
  benign=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: localhost' \
    "http://127.0.0.1:$WAF_PORT/get?hello=world")
  attack=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: localhost' \
    --data "id=1' or '1'='1" "http://127.0.0.1:$WAF_PORT/post")
  log "PL$pl: sanity — benign=$benign attack=$attack"
  [ "$benign" = "200" ] || die "sanity: benign request returned $benign, expected 200"
  if [ "$MODE" = "cloud" ]; then
    [ "$attack" = "403" ] || die "sanity: SQLi payload returned $attack, expected 403"
  else
    # DetectionOnly: the payload must be *recorded*, not blocked. Both halves
    # matter — a 403 here would mean log_only_mode did not take, and a missing
    # log line would mean the whole run is about to score 0 for a plumbing
    # reason. Also proves the marker protocol works end to end.
    [ "$attack" = "200" ] || die "sanity: log mode must not block, but SQLi payload returned $attack"
    curl -s -o /dev/null -H 'Host: localhost' -H 'X-CRS-Test: sanity-marker' \
      "http://127.0.0.1:$WAF_PORT/get"
    local waited=0
    for _ in $(seq 1 40); do
      if grep -q '\[id "942100"\]' "$auditlog" && grep -qi 'x-crs-test: sanity-marker' "$auditlog"; then
        waited=1; break
      fi
      sleep 0.25
    done
    [ "$waited" = "1" ] || {
      tail -20 "$auditlog" >&2
      die "sanity: audit log has no CRS-942100 hit and/or no X-CRS-Test marker (see $auditlog)"
    }
    log "PL$pl: sanity — audit log records rule hits and markers"
  fi

  log "PL$pl: running go-ftw ($MODE mode) over $CRS_DIR/tests/regression/tests"
  local ftw_mode_args=()
  if [ "$MODE" = "cloud" ]; then
    ftw_mode_args=(--cloud --overrides "$BLOCKING_OVERRIDES")
  fi
  set +e
  "$GOBIN/go-ftw" run \
    --config "$ftw_conf" \
    "${ftw_mode_args[@]}" \
    -d "$CRS_DIR/tests/regression/tests/" \
    -o json \
    -f "$results" \
    $FTW_ARGS >"$OUT/ftw-pl$pl.stdout" 2>"$OUT/ftw-pl$pl.stderr"
  local ftw_rc=$?
  set -e
  log "PL$pl: go-ftw exited $ftw_rc (non-zero simply means some tests failed)"
  [ -s "$results" ] || { tail -5 "$OUT/ftw-pl$pl.stderr" >&2; die "PL$pl: go-ftw produced no results"; }

  # Each quarantined `retry_once` test, on its own, with an unmodified config.
  # A run that aborts is that one test failing; anything else is its real
  # verdict. Merged back into the headline number by classify.py, so the
  # denominator stays the full corpus and nothing is quietly dropped.
  local retry_results="$OUT/retry-once-pl$pl.json"
  local retry_dir="$WORK/retry-once-pl$pl"
  rm -rf "$retry_dir"; mkdir -p "$retry_dir"
  for tid in $RETRY_ONCE_IDS; do
    set +e
    "$GOBIN/go-ftw" run \
      --config "$WORK/.ftw-solo-pl$pl.yaml" \
      "${ftw_mode_args[@]}" \
      -d "$CRS_DIR/tests/regression/tests/" \
      --include "^$tid\$" \
      -o json \
      -f "$retry_dir/$tid.json" \
      >/dev/null 2>&1
    set -e
  done
  python3 - "$retry_dir" "$retry_results" <<'PY' || die "merging retry_once results failed"
import json, os, sys
src, dst = sys.argv[1], sys.argv[2]
merged = {"success": [], "failed": [], "triggered-rules": {}}
for name in sorted(os.listdir(src)):
    tid = name.removesuffix(".json")
    path = os.path.join(src, name)
    try:
        with open(path, encoding="utf-8") as fh:
            stats = json.load(fh)
    except (OSError, ValueError):
        # go-ftw aborted before writing anything: the test failed twice.
        merged["failed"].append(tid)
        continue
    merged["success"].extend(stats.get("success") or [])
    merged["failed"].extend(stats.get("failed") or [])
    merged["failed"].extend(stats.get("forced-fail") or [])
    merged["triggered-rules"].update(stats.get("triggered-rules") or {})
    if tid not in merged["success"] and tid not in merged["failed"]:
        # Ran, but produced no verdict for the test we asked for. Never a pass.
        merged["failed"].append(tid)
with open(dst, "w", encoding="utf-8") as fh:
    json.dump(merged, fh)
print(f"retry_once re-run: {len(merged['success'])} passed, {len(merged['failed'])} failed")
PY

  log "PL$pl: classifying"
  local extra=()
  [ "$APPLY_EXCLUSIONS" = "1" ] && extra+=(--apply-exclusions)
  [ -n "$BASELINE" ] && extra+=(--baseline "$BASELINE")
  # --replay needs the WAF up, so it runs before the process is torn down.
  # In cloud mode it supplies both the status and the blocking rule's name. In
  # log mode the rule attribution comes from go-ftw itself (`triggered-rules`),
  # which is exact rather than inferred from a block page — but the replay is
  # still what separates "we did not detect this" from "Pingora answered 400
  # before the WAF saw the request", which is true in DetectionOnly too.
  [ "$REPLAY" = "1" ] && extra+=(--replay "127.0.0.1:$WAF_PORT")

  set +e
  python3 "$SCRIPT_DIR/classify.py" \
    --results "$results" \
    --extra-results "$retry_results" \
    --crs "$CRS_DIR" \
    --rules "$SRC/rules/owasp-crs" \
    --exclusions "$SCRIPT_DIR/exclusions.yaml" \
    --waf-log "$waflog" \
    --paranoia "$pl" \
    --mode "$MODE" \
    --crs-version "$CRS_VERSION" \
    --json-out "$OUT/report-pl$pl.json" \
    --replay-cache "$OUT/replay-cache-pl$pl.json" \
    "${extra[@]}" | tee "$OUT/report-pl$pl.txt"
  local classify_rc=${PIPESTATUS[0]}
  set -e

  stop_waf
  reset_schema

  [ "$classify_rc" = "0" ] || die "PL$pl regressed against $BASELINE"
}

IFS=',' read -r -a PLS <<<"$PL"
for pl in "${PLS[@]}"; do
  run_pl "$pl"
done

log "reports in $OUT"
