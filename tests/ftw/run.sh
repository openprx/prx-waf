#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# OWASP CRS official regression suite (go-ftw) against prx-waf.
#
#   tests/ftw/run.sh              # paranoia level 1 (factory default)
#   PL=2 tests/ftw/run.sh         # paranoia level 2
#   PL=1,2,4 tests/ftw/run.sh     # several levels in one go
#
# Brings up everything it needs, runs the suite, prints a classified report and
# tears the environment down again. Nothing is left running and nothing is
# written outside $WORK (default: a directory under $TMPDIR) except the report
# files, which land in $OUT (default: $WORK/reports).
#
# ── How the verdict is reached ───────────────────────────────────────────────
# go-ftw runs in **cloud mode**: it never reads the WAF's logs, it only looks at
# the HTTP status code. A test that expects a rule to fire passes iff the
# response is 403; a test that expects no rule to fire passes iff the response
# is 200, 404 or 405 (go-ftw check/status.go, `negativeExpectedStatuses`). This
# is the only mode that is meaningful for a non-ModSecurity engine: the log
# mode's `X-CRS-Test` marker protocol is a ModSecurity audit-log convention.
#
# ── What is measured ─────────────────────────────────────────────────────────
# The CRS check only. Every prx-waf-native Lane 1 detector (sqli/xss/rce/…) and
# the Lane 2 semantic engine are switched OFF for the run, so a pass can only
# come from a CRS rule and a false positive can only come from a CRS rule. That
# is what makes the number comparable to ModSecurity+CRS or Coraza+CRS.
# Rate limiting (`cc`) is also off: go-ftw fires ~4.7k requests from one IP.
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
gen_config() {                      # $1 = paranoia level, $2 = output path
  local pl="$1" dst="$2"
  {
    cat <<EOF
# Generated by tests/ftw/run.sh — do not edit, do not commit.
# CRS regression harness, paranoia level $pl.
[proxy]
listen_addr = "127.0.0.1:$WAF_PORT"
listen_addr_tls = "127.0.0.1:$WAF_TLS_PORT"
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

[rules]
dir = "rules/"
hot_reload = false
enable_builtin_owasp = true
enable_builtin_bot = false
enable_builtin_scanner = false
EOF
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
FTW_CONF="$WORK/.ftw.yaml"
cat >"$FTW_CONF" <<EOF
# Generated by tests/ftw/run.sh.
# cloud mode: verdicts come from HTTP status codes only, never from WAF logs.
mode: cloud
testoverride:
  input:
    dest_addr: "127.0.0.1"
    port: $WAF_PORT
EOF

# The CRS corpus asserts on ModSecurity's DetectionOnly audit log and carries
# almost no `output.status`. go-ftw's cloud mode returns *true* whenever a test
# has no status expectation (check/status.go: `if c.expected.Status == 0`), so
# without this file a cloud run asserts nothing and reports ~100%. The generator
# restates each existing log assertion as its blocking-mode status code and
# changes nothing else — see the header of gen_overrides.py.
BLOCKING_OVERRIDES="$WORK/blocking-mode-overrides.yaml"
log "generating blocking-mode status expectations"
python3 "$SCRIPT_DIR/gen_overrides.py" --crs "$CRS_DIR" --out "$BLOCKING_OVERRIDES"

# ── Run one paranoia level ───────────────────────────────────────────────────
run_pl() {
  local pl="$1"
  local cfg="$WORK/prx-waf-pl$pl.toml"
  local waflog="$WORK/prx-waf-pl$pl.log"
  local results="$OUT/results-pl$pl.json"

  gen_config "$pl" "$cfg"

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

  # Sanity gate: the harness is worthless if a known-blocking payload is not
  # blocked and a benign request is not passed. Fail loudly rather than
  # reporting a 0% that is really a wiring bug.
  local benign attack
  benign=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: localhost' \
    "http://127.0.0.1:$WAF_PORT/get?hello=world")
  attack=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: localhost' \
    --data "id=1' or '1'='1" "http://127.0.0.1:$WAF_PORT/post")
  log "PL$pl: sanity — benign=$benign attack=$attack"
  [ "$benign" = "200" ] || die "sanity: benign request returned $benign, expected 200"
  [ "$attack" = "403" ] || die "sanity: SQLi payload returned $attack, expected 403"

  log "PL$pl: running go-ftw over $CRS_DIR/tests/regression/tests"
  set +e
  "$GOBIN/go-ftw" run \
    --config "$FTW_CONF" \
    --cloud \
    --overrides "$BLOCKING_OVERRIDES" \
    -d "$CRS_DIR/tests/regression/tests/" \
    -o json \
    -f "$results" \
    $FTW_ARGS >"$OUT/ftw-pl$pl.stdout" 2>"$OUT/ftw-pl$pl.stderr"
  local ftw_rc=$?
  set -e
  log "PL$pl: go-ftw exited $ftw_rc (non-zero simply means some tests failed)"

  log "PL$pl: classifying"
  local extra=()
  [ "$APPLY_EXCLUSIONS" = "1" ] && extra+=(--apply-exclusions)
  [ -n "$BASELINE" ] && extra+=(--baseline "$BASELINE")
  # --replay needs the WAF up, so it runs before the process is torn down.
  [ "$REPLAY" = "1" ] && extra+=(--replay "127.0.0.1:$WAF_PORT")

  set +e
  python3 "$SCRIPT_DIR/classify.py" \
    --results "$results" \
    --crs "$CRS_DIR" \
    --rules "$SRC/rules/owasp-crs" \
    --exclusions "$SCRIPT_DIR/exclusions.yaml" \
    --waf-log "$waflog" \
    --paranoia "$pl" \
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
