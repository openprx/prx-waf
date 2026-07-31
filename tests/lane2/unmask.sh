#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Ask what every Lane 2 rule actually matches, rather than what it gets named on.
#
#   tests/lane2/unmask.sh                          # every rule, one run each
#   tests/lane2/unmask.sh xss.base_href sql.stacked
#
# Read the result with `unmask.py`.
#
# ── Why price-rules.sh cannot answer this ────────────────────────────────────
# `SemanticDetector::detect` returns ONE finding, so a detector names at most one
# rule per view — the strongest one the operator has left enabled. A weaker rule
# that matches the same view is not reported, is not in `rule_keys_fired`, and is
# therefore not in any column `price-rules.py` computes. It reads as zero.
#
# That is not hypothetical. `xss.base_href` prices at `touched = 0` on a corpus
# whose `content-010` row IS a `<base href>` trap, because `xss.script_tag`
# outranks it on the same field; `traversal.plain_dotdot` stopped appearing on
# `trav-005` the moment `traversal.sensitive_abs_ops` went default-on. Both rules
# match. Neither is named.
#
# ── The experiment ──────────────────────────────────────────────────────────
# One run per rule. The rule is enabled and every OTHER rule of its own detector
# is disabled, so nothing is left to outrank it and every row it matches names
# it. The other twelve detectors are untouched, which keeps the views, the
# request budget and the rest of the pipeline identical to the baseline's —
# `NORMALISED_STRONG_STRUCTURE` reads the compiled-in `default_on` rather than
# these toggles, so the view set is the same in every run of this sweep.
#
# Solo rather than a peel is deliberate. A peel that disables the strongest rule
# and re-runs also works, but it has to argue about tie-breaks (`best_match`
# keeps the incumbent, `max_by_key` in the shell-AST walker keeps the last) and
# about how deep is deep enough. Isolating one rule leaves nothing to argue
# about, and a run is twenty seconds.
#
# Shadow only: `rule_keys_fired` comes from the `semantic_observations` rows,
# which only shadow mode writes. An enforce replay would add HTTP status codes
# and no attribution, which is not what this sweep is for.
#
# ── What it cannot reach ────────────────────────────────────────────────────
# Three losses are not a rule outranking a rule and no toggle undoes them:
#   * `ast.comment_obfusc` replaces the AST structure's key on any view carrying
#     a comment marker, and is deliberately not switchable;
#   * the shell-AST walk records `rce_ast.cmd_subst` or `rce_ast.cmd_subst_any`
#     for a substitution, never both — the choice is the inner text, not config;
#   * a `SetExpr::SetOperation` body reports `ast.union` or nothing, so the
#     structures inside a UNION's selects are unreachable with `ast.union` off.
# Each makes the affected rule's count a floor. `unmask.py` says which.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"

WORK="${WORK:-${TMPDIR:-/tmp}/prx-waf-lane2-unmask}"
OUT="${OUT:-$WORK/runs}"
PRXWAF_BIN="${PRXWAF_BIN:-}"
# A port block of its own so a pricing sweep and an unmasking sweep can run on
# the same box without measuring each other.
export WAF_PORT="${WAF_PORT:-18511}"
export WAF_TLS_PORT="${WAF_TLS_PORT:-18544}"
export API_PORT="${API_PORT:-18599}"
export BACKEND_PORT="${BACKEND_PORT:-18588}"
export PG_PORT="${PG_PORT:-15809}"
export PG_CONTAINER="${PG_CONTAINER:-prx-waf-lane2-unmask-pg}"

log() { printf '\033[1;36m[unmask]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31m[unmask] %s\033[0m\n' "$*" >&2; exit 1; }

mkdir -p "$WORK" "$OUT"

# ── One Postgres for the whole sweep ─────────────────────────────────────────
# Same reason as price-rules.sh: run.sh's own per-invocation container churn
# fails on the second invocation because the port is not released in time.
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
# Symlinks except for `configs/`, which is the one real directory, so the
# repository is never written to while the sweep runs. Same device as
# price-rules.sh, and for the same reason.
MIRROR="$WORK/src"
rm -rf "$MIRROR"
mkdir -p "$MIRROR/configs"
for entry in "$REPO_ROOT"/*; do
  name="$(basename "$entry")"
  [ "$name" = "configs" ] && continue
  ln -s "$entry" "$MIRROR/$name"
done

INVENTORY="$WORK/inventory.json"
"$PRXWAF_BIN" rules semantic --format json >"$INVENTORY"

# ── One experiment ───────────────────────────────────────────────────────────
# $1 = tag, $2 = rules_enabled csv, $3 = rules_disabled csv.
run_one() {
  local tag="$1" enable="${2:-}" disable="${3:-}"
  local dst="$OUT/$tag"
  if [ -f "$dst/report-shadow.json" ]; then
    log "$tag — already measured, skipping"
    return 0
  fi
  rm -rf "$dst"; mkdir -p "$dst"
  cp "$REPO_ROOT"/configs/*.toml "$MIRROR/configs/"

  python3 - "$MIRROR/configs/default.toml" "$REPO_ROOT/configs/default.toml" \
           "$enable" "$disable" <<'PY'
import sys
dst, src, enable, disable = sys.argv[1:5]
text = open(src, encoding="utf-8").read()
# Both substitutions must bite. A default.toml that stopped carrying either line
# would be measured once per rule as the baseline, and the sweep would report
# that no rule is masked anywhere.
for switch, keys in (("rules_enabled", enable), ("rules_disabled", disable)):
    anchor = f"\n{switch} = []\n"
    if text.count(anchor) != 1:
        sys.exit(f"configs/default.toml drift: `{switch} = []` is not there exactly once")
    body = ", ".join(f'"{k}"' for k in keys.split(",") if k)
    text = text.replace(anchor, f"\n{switch} = [{body}]\n")
open(dst, "w", encoding="utf-8").write(text)
PY

  log "$tag — replaying the corpus"
  WORK="$WORK/run" OUT="$dst" SRC="$MIRROR" PRXWAF_BIN="$PRXWAF_BIN" \
  MODE="shadow" RECORDED_FROM="unmask/$tag" \
    "$SCRIPT_DIR/run.sh" >"$dst/run.log" 2>&1 \
    || { tail -20 "$dst/run.log" >&2; die "$tag failed, see $dst/run.log"; }
}

if [ "$#" -gt 0 ]; then
  KEYS=("$@")
else
  mapfile -t KEYS < <(python3 -c '
import json, sys
print("\n".join(r["rule_key"] for r in json.load(open(sys.argv[1]))))' "$INVENTORY")
fi
log "${#KEYS[@]} rule(s) to unmask, plus the baseline"

# The baseline is the shipped posture, and it is what every count is read
# against: a rule that fires on N rows here and N rows solo was never masked.
run_one baseline "" ""

for key in "${KEYS[@]}"; do
  # Every sibling of the rule's own detector goes off. Nothing else moves —
  # masking is only ever between two rules of one detector on one view.
  read -r enable disable <<<"$(python3 -c '
import json, sys
inv = json.load(open(sys.argv[1]))
key = sys.argv[2]
me = next((r for r in inv if r["rule_key"] == key), None)
if me is None:
    sys.exit(f"no such rule: {key}")
sibs = [r["rule_key"] for r in inv
        if r["detector"] == me["detector"] and r["rule_key"] != key]
print("-" if me["default_on"] else key, ",".join(sorted(sibs)))' "$INVENTORY" "$key")"
  [ "$enable" = "-" ] && enable=""
  run_one "solo-$key" "$enable" "$disable"

  # A default-ON rule's priced contact is readable straight out of the baseline
  # — it is already running, so the rows it is named on are the rows the pricing
  # sweep recorded. A default-OFF rule is named on nothing there, so the number
  # its price was taken at needs its own run: the rule alone, added to the
  # shipped posture, which is exactly what `price-rules.sh` substitutes.
  if [ -n "$enable" ]; then
    run_one "priced-$key" "$key" ""
  fi
done

log "reports in $OUT — read them with:"
log "  python3 $SCRIPT_DIR/unmask.py --dir $OUT"
