#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# The two controlled experiments behind results/worker-threads-*.json and
# results/smt-control-*.json.
#
#   tests/perf/scaling.sh curve     # worker_threads = 1 / 2 / 4, one core set
#   tests/perf/scaling.sh smt       # 4 workers on 2 physical cores vs on 4
#   tests/perf/scaling.sh both
#
# Why this is a script and not a paragraph in RESULTS.md: both experiments are
# several run.sh invocations that only mean anything TOGETHER, and every one of
# them has to hold something fixed that a reader retyping the commands would
# quietly get wrong. Two of those are easy to miss.
#
#   * The harness pins the WAF, the origin and the generator, but not ITSELF.
#     run.sh's shell, its awk/jq children and the 5 Hz RSS sampler inherit
#     whatever affinity they were launched with, and if that overlaps the
#     subject's cores they are a contaminant no pinning argument describes. So
#     every invocation below is wrapped in its own taskset.
#   * CPUs 0-3 on this class of host are TWO physical cores presented as four
#     hardware threads (check thread_siblings_list). "4 workers on 4 CPUs" and
#     "4 workers on 4 cores" are different experiments and the difference is
#     most of the answer, which is what the `smt` mode exists to measure.
#
# Results land in $OUT_ROOT/<arm>/summary.json. Copy the ones you mean to keep
# into results/ by hand — this script deliberately does not write there, so a
# published file is always something a human chose to publish.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"

MODE="${1:-both}"
OUT_ROOT="${OUT_ROOT:-${TMPDIR:-/tmp}/prx-waf-scaling}"

# Held identical across every arm of both experiments.
export ROUNDS="${ROUNDS:-3}"
export DURATION="${DURATION:-10}"
export WARMUP="${WARMUP:-3}"
export CONNECTIONS="${CONNECTIONS:-50}"
export PRXWAF_BIN="${PRXWAF_BIN:-$REPO_ROOT/target/release/prx-waf}"

# One Postgres for the whole session rather than one per invocation: bringing a
# container up and down between arms is a source of failure that has nothing to
# do with what is being measured, and a container the operator can see by name
# is one they can check for before starting anything else on the host.
export PG_CONTAINER="${PG_CONTAINER:-prx-waf-scaling-pg}"
export PG_PORT="${PG_PORT:-15533}"

log() { printf '\033[1;35m[scaling]\033[0m %s\n' "$*"; }

start_pg() {
  local cli
  cli="$(command -v podman || command -v docker)" || {
    echo "need podman or docker" >&2; exit 1; }
  "$cli" rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true
  "$cli" run -d --name "$PG_CONTAINER" \
    -e POSTGRES_USER=prx_waf -e POSTGRES_PASSWORD=prx_waf -e POSTGRES_DB=prx_waf \
    -p "127.0.0.1:$PG_PORT:5432" "${POSTGRES_IMAGE:-docker.io/library/postgres:16}" \
    >/dev/null
  local i
  for i in $(seq 1 60); do
    "$cli" exec "$PG_CONTAINER" pg_isready -U prx_waf >/dev/null 2>&1 && return 0
    sleep 1
  done
  echo "postgres did not become ready" >&2
  exit 1
}

stop_pg() {
  local cli
  cli="$(command -v podman || command -v docker)" || return 0
  "$cli" rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true
}

# $1 arm name, $2 harness cpus, $3 WAF cpus, $4 worker threads,
# $5 origin cpus, $6 generator cpus
arm() {
  local name="$1" harness="$2" waf="$3" threads="$4" origin="$5" gen="$6"
  log "arm $name: waf=$waf threads=$threads origin=$origin gen=$gen (harness $harness)"
  log "  loadavg before: $(awk '{print $1}' /proc/loadavg)"
  mkdir -p "$OUT_ROOT/$name"
  SKIP_POSTGRES=1 \
  OUT="$OUT_ROOT/$name" \
  WAF_CPUS="$waf" WORKER_THREADS="$threads" \
  ORIGIN_CPUS="$origin" LOAD_CPUS="$gen" \
  POSTURES="$POSTURES" WORKLOADS="$WORKLOADS" \
    taskset -c "$harness" "$SCRIPT_DIR/run.sh"
}

# ── The scaling curve ────────────────────────────────────────────────────────
# One core set, one rig, one tree; the ONLY thing that moves is the thread
# count. This is what §1 of RESULTS.md needed and did not have: its ×2.32 was
# the shipped 4-thread default against a different tree's single-threaded
# default, which conflates the thread count with every other commit between
# them.
curve() {
  POSTURES="${POSTURES:-origin,passthrough,lane1,full}"
  WORKLOADS="${WORKLOADS:-get-small,json-post,form-post,multipart,body-1mb}"
  local t
  for t in 1 2 4; do
    arm "threads-$t" 4-15 0-3 "$t" 4-9 10-15
  done
}

# ── SMT versus contention ────────────────────────────────────────────────────
# Same four workers, same rig, same everything — two physical cores in one arm
# and four in the other. The rig is smaller than the curve's on purpose: four
# physical cores for the subject leaves only 8-15 for the origin and the
# generator, so these arms are comparable to EACH OTHER and not to the curve.
# The `origin` posture is measured in every arm as the rig's own ceiling, which
# is what says whether a number is the WAF's limit or the generator's.
smt() {
  POSTURES="${POSTURES:-origin,passthrough,full}"
  WORKLOADS="${WORKLOADS:-get-small,json-post}"
  arm smt4  8-15 0-3     4 8-11 12-15
  arm smt1  8-15 0-3     1 8-11 12-15
  arm phys4 8-15 0,2,4,6 4 8-11 12-15
  arm phys1 8-15 0,2,4,6 1 8-11 12-15
  arm wide4 8-15 0-7     4 8-11 12-15
}

case "$MODE" in
  curve) start_pg; trap stop_pg EXIT; curve ;;
  smt)   start_pg; trap stop_pg EXIT; smt ;;
  both)  start_pg; trap stop_pg EXIT; curve; smt ;;
  *) echo "usage: scaling.sh [curve|smt|both]" >&2; exit 1 ;;
esac

log "summaries under $OUT_ROOT/*/summary.json"
