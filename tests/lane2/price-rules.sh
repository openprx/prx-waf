#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Price the Lane 2 rules, one at a time, against both halves of the corpus.
#
#   tests/lane2/price-rules.sh                       # every default-off rule
#   tests/lane2/price-rules.sh sql.stacked ssti.getclass
#   COMBO=recommended:nosql.expr_operator,xxe.entity_expansion \
#     tests/lane2/price-rules.sh                     # ... plus a named combination
#   DIRECTION=disable tests/lane2/price-rules.sh     # every default-ON rule
#
# Every Lane 2 rule ships either on or off, and the ones that ship off are the
# ones nobody has priced. `[content_security] rules_enabled` makes the question
# askable; this script asks it. For each rule it runs the whole corpus in both
# modes with that ONE rule switched on and nothing else changed, so the delta
# against the untouched baseline run is that rule's bill: what it recovers on
# the attack half, and — the number that actually decides anything — what it
# costs on the benign half.
#
# Read the result with `price-rules.py`, which diffs each run against the
# baseline and prints the per-rule table.
#
# ── Both directions ─────────────────────────────────────────────────────────
# DIRECTION=enable (the default) sweeps the default-off rules through
# `rules_enabled`, and prices a rule nobody has ever run.
#
# DIRECTION=disable sweeps the default-ON rules through `rules_disabled`, and
# prices a rule that has been running all along. It is the same experiment
# pointed the other way, and it exists because the enable sweep answered a
# question about rules that are off while leaving the same question unasked
# about the ones that are on: which running rules are in contact with benign
# traffic and are held off the false positive list by nothing more than the
# distance to a threshold. That contact is invisible in the shipped posture —
# the rule is already on, so no bucket delta, no FP count and no fp-block count
# moves — and the only way to see it is to take the rule away and look at what
# stops firing. The baseline is the same untouched run in both directions;
# `price-rules.py --direction disable` reverses the subtraction so every column
# still reads as what the rule does when it is ON.
#
# ── Why it mirrors the tree instead of editing configs/default.toml ──────────
# `run.sh` slices the `[content_security]` block out of `$SRC/configs/default.toml`
# so a run always measures the posture that ships. To switch one rule on, the
# experiment therefore has to change that file — and changing it in place would
# leave the working tree dirty for as long as the sweep runs, which is hours, and
# would lose the operator's edit if the sweep died half way. So $WORK gets a
# mirror of the repository made of symlinks, with `configs/` the one real
# directory in it, and the substitution happens there. The repository is never
# written to.
#
# ── The experiment is only valid one rule at a time ─────────────────────────
# Switching every default-off rule on at once produces one mixed number that
# prices nothing: a benign request flagged by the union of thirty-eight rules
# names no rule to leave off. Combinations are still worth measuring — several
# rules can corroborate on the same request, so a combination is NOT the sum of
# its parts — which is what COMBO is for, but a combination is a hypothesis to
# check after the per-rule sweep, not a substitute for it.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"

WORK="${WORK:-${TMPDIR:-/tmp}/prx-waf-lane2-pricing}"
OUT="${OUT:-$WORK/pricing}"
PRXWAF_BIN="${PRXWAF_BIN:-}"
# enable  — sweep the default-off rules through `rules_enabled`
# disable — sweep the default-on rules through `rules_disabled`
DIRECTION="${DIRECTION:-enable}"
# One combination per entry, `name:key,key,...`; several separated by spaces.
COMBO="${COMBO:-}"
# Ports and Postgres are handed to run.sh unchanged if the caller set them.
export WAF_PORT="${WAF_PORT:-17911}"
export WAF_TLS_PORT="${WAF_TLS_PORT:-17944}"
export API_PORT="${API_PORT:-17999}"
export BACKEND_PORT="${BACKEND_PORT:-17988}"
export PG_PORT="${PG_PORT:-15803}"
export PG_CONTAINER="${PG_CONTAINER:-prx-waf-lane2-pricing-pg}"

log() { printf '\033[1;36m[price]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31m[price] %s\033[0m\n' "$*" >&2; exit 1; }

case "$DIRECTION" in
  enable)  SWITCH_KEY="rules_enabled";  INVENTORY_STATE="off" ;;
  disable) SWITCH_KEY="rules_disabled"; INVENTORY_STATE="on" ;;
  *) die "DIRECTION must be enable or disable, got '$DIRECTION'" ;;
esac

mkdir -p "$WORK" "$OUT"

# ── One Postgres for the whole sweep ─────────────────────────────────────────
# `run.sh` starts and removes its own container per invocation. Across forty
# back-to-back invocations that is forty container churns, and the second one
# fails outright: the port check runs before the previous container's port has
# been released, so the sweep dies one rule in with "port is already in use".
# So the sweep owns the database and hands `run.sh` SKIP_POSTGRES=1.
POSTGRES_IMAGE="${POSTGRES_IMAGE:-docker.io/library/postgres:16}"
OWN_POSTGRES=0
if [ "${SKIP_POSTGRES:-0}" != "1" ]; then
  command -v psql >/dev/null 2>&1 \
    || die "the sweep reads results through a host psql; install postgresql-client, or start your own Postgres on :$PG_PORT and export SKIP_POSTGRES=1"
  CONTAINER_CLI="${CONTAINER_CLI:-}"
  if [ -z "$CONTAINER_CLI" ]; then
    if command -v podman >/dev/null 2>&1; then CONTAINER_CLI=podman
    elif command -v docker >/dev/null 2>&1; then CONTAINER_CLI=docker
    else die "need podman or docker"; fi
  fi
  log "starting postgres ($PG_CONTAINER on :$PG_PORT) for the whole sweep"
  "$CONTAINER_CLI" rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true
  "$CONTAINER_CLI" run -d --name "$PG_CONTAINER" \
    -e POSTGRES_USER=prx_waf -e POSTGRES_PASSWORD=prx_waf -e POSTGRES_DB=prx_waf \
    -p "127.0.0.1:$PG_PORT:5432" "$POSTGRES_IMAGE" >/dev/null
  OWN_POSTGRES=1
  for _ in $(seq 1 60); do
    "$CONTAINER_CLI" exec "$PG_CONTAINER" pg_isready -U prx_waf >/dev/null 2>&1 && break
    sleep 1
  done
  "$CONTAINER_CLI" exec "$PG_CONTAINER" pg_isready -U prx_waf >/dev/null 2>&1 \
    || die "postgres did not become ready"
  export SKIP_POSTGRES=1
fi
teardown() {
  local rc=$?
  [ "$OWN_POSTGRES" = "1" ] && "$CONTAINER_CLI" rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true
  return $rc
}
trap teardown EXIT

if [ -z "$PRXWAF_BIN" ]; then
  log "building prx-waf (release)"
  ( cd "$REPO_ROOT" && cargo build --release -p prx-waf )
  PRXWAF_BIN="${CARGO_TARGET_DIR:-$REPO_ROOT/target}/release/prx-waf"
fi
[ -x "$PRXWAF_BIN" ] || die "prx-waf binary not found: $PRXWAF_BIN"

# ── The mirror tree ──────────────────────────────────────────────────────────
MIRROR="$WORK/src"
rm -rf "$MIRROR"
mkdir -p "$MIRROR/configs"
for entry in "$REPO_ROOT"/*; do
  name="$(basename "$entry")"
  [ "$name" = "configs" ] && continue
  ln -s "$entry" "$MIRROR/$name"
done
cp "$REPO_ROOT"/configs/*.toml "$MIRROR/configs/"

# ── The rules to price ───────────────────────────────────────────────────────
if [ "$#" -gt 0 ]; then
  RULES=("$@")
else
  log "reading the default-$INVENTORY_STATE inventory out of the binary"
  mapfile -t RULES < <(
    "$PRXWAF_BIN" rules semantic --state "$INVENTORY_STATE" --format json 2>/dev/null \
      | python3 -c 'import json,sys; [print(r["rule_key"]) for r in json.load(sys.stdin)]'
  )
fi
[ "${#RULES[@]}" -gt 0 ] || die "no rules to price"
log "$DIRECTION sweep: ${#RULES[@]} rule(s) to price, plus the baseline"

# ── One experiment ───────────────────────────────────────────────────────────
# $1 = tag, $2 = comma-separated rule keys ("" for the baseline).
run_one() {
  local tag="$1" keys="${2:-}"
  local dst="$OUT/$tag"
  if [ -f "$dst/report-enforce.json" ]; then
    log "$tag — already measured, skipping"
    return 0
  fi
  rm -rf "$dst"; mkdir -p "$dst"

  python3 - "$MIRROR/configs/default.toml" "$REPO_ROOT/configs/default.toml" "$keys" \
           "$SWITCH_KEY" <<'PY'
import sys
dst, src, keys, switch = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
text = open(src, encoding="utf-8").read()
anchor = f"\n{switch} = []\n"
# The substitution must bite. A default.toml that stopped carrying this line
# would otherwise be measured once per rule as the baseline, and the sweep would
# report that no rule costs anything — or, in the disable direction, that no
# running rule contributes anything.
if text.count(anchor) != 1:
    sys.exit(f"configs/default.toml drift: `{switch} = []` is not there exactly once")
body = ", ".join(f'"{k}"' for k in keys.split(",") if k)
open(dst, "w", encoding="utf-8").write(text.replace(anchor, f"\n{switch} = [{body}]\n"))
PY

  log "$tag — replaying both modes"
  WORK="$WORK/run" OUT="$dst" SRC="$MIRROR" PRXWAF_BIN="$PRXWAF_BIN" \
  MODE="shadow,enforce" RECORDED_FROM="price-rules/$DIRECTION/$tag" \
    "$SCRIPT_DIR/run.sh" >"$dst/run.log" 2>&1 \
    || { tail -20 "$dst/run.log" >&2; die "$tag failed, see $dst/run.log"; }
}

run_one baseline ""
for rule in "${RULES[@]}"; do
  run_one "$rule" "$rule"
done
for combo in $COMBO; do
  run_one "combo-${combo%%:*}" "${combo#*:}"
done

log "reports in $OUT — read them with:"
log "  python3 $SCRIPT_DIR/price-rules.py --dir $OUT --direction $DIRECTION"
