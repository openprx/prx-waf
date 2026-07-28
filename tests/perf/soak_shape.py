#!/usr/bin/env python3
"""Classify the memory curve a `soak.sh` run produced.

The question `tests/perf/RESULTS.md` §6 leaves open is not "how much memory did
it use" but "what shape is the curve", and those need different arithmetic. A
peak is a summary of the past; a shape is a claim about the future, so the rule
that produces it has to be written down rather than eyeballed off a graph.

The rule, stated once:

* fit a least-squares line to the **second half** of the RSS series. The first
  half contains startup, JIT-free warmup, allocator arena growth and the
  connection pool filling — all real, all bounded, and all irrelevant to whether
  the process settles;
* compare that slope against the first half's. A process that has converged has
  a second-half slope near zero **and** far below its first-half slope;
* read the drop counters. A flat curve with drops is a *bounded* system doing
  what its bound says; a flat curve with no drops is a *converged* one. Those
  are different claims and the operator needs to know which they have.

No verdict is emitted without the numbers it came from, and a run that was
aborted at the RSS ceiling reports that first — nothing downstream of an abort
is a measurement of steady state.
"""

from __future__ import annotations

import csv
import json
import sys

# A second-half slope at or below this is treated as flat. One MiB per minute is
# ~1.4 GiB a day, which is not "stable" in any absolute sense — it is the
# resolution below which this harness, sampling RSS at 1 Hz on a host with other
# processes on it, cannot honestly distinguish a trend from allocator noise.
FLAT_MIB_PER_MIN = 1.0

# How much smaller than the first half the second half must be before "it
# levelled off" is a defensible reading rather than a hopeful one.
DECAY_RATIO = 0.2


def fit(xs: list[float], ys: list[float]) -> tuple[float, float]:
    """Least-squares slope and R^2. Slope is in ys-units per xs-unit."""
    n = len(xs)
    if n < 3:
        return 0.0, 0.0
    mx = sum(xs) / n
    my = sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    if sxx == 0:
        return 0.0, 0.0
    slope = sxy / sxx
    syy = sum((y - my) ** 2 for y in ys)
    r2 = (sxy * sxy) / (sxx * syy) if syy > 0 else 0.0
    return slope, r2


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: soak_shape.py <series.csv> <meta.json>", file=sys.stderr)
        return 2
    csv_path, meta_path = sys.argv[1], sys.argv[2]

    with open(meta_path, encoding="utf-8") as fh:
        meta = json.load(fh)

    rows = []
    settled_kb = None
    with open(csv_path, encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            if row["t_s"] == "settled_after_load_stopped":
                settled_kb = int(row["rss_kb"] or 0)
                continue
            try:
                rows.append({k: (v or "0") for k, v in row.items()})
            except (TypeError, ValueError):
                continue

    if len(rows) < 6:
        print(f"soak_shape: only {len(rows)} samples — too few to say anything")
        return 1

    t = [float(r["t_s"]) for r in rows]
    rss = [int(r["rss_kb"]) / 1024.0 for r in rows]
    q_attack = [int(r["q_attack_log"]) for r in rows]
    q_secev = [int(r["q_security_event"]) for r in rows]
    drops = {
        "attack_log": int(rows[-1]["drop_attack_log"]),
        "security_event": int(rows[-1]["drop_security_event"]),
        "semantic_obs": int(rows[-1]["drop_semantic_obs"]),
        "semantic_events": int(rows[-1]["drop_semantic_events"]),
        "audit_log": int(rows[-1]["drop_audit_log"]),
    }
    total_drops = sum(drops.values())

    half = len(rows) // 2
    s1, r1 = fit(t[:half], rss[:half])
    s2, r2 = fit(t[half:], rss[half:])
    s1_min, s2_min = s1 * 60.0, s2 * 60.0
    qs, _ = fit(t[half:], [float(v) for v in q_attack[half:]])

    aborted = meta.get("aborted") or ""
    flat = abs(s2_min) <= FLAT_MIB_PER_MIN or (s1_min > 0 and s2_min <= s1_min * DECAY_RATIO)

    if aborted:
        shape = "UNBOUNDED"
        why = (
            f"the run stopped early: {aborted}. It never reached a steady state to "
            f"measure, which is itself the answer at this traffic rate."
        )
    elif flat and total_drops > 0:
        shape = "BOUNDED BY A DROP POLICY"
        why = (
            f"RSS levelled off ({s2_min:+.2f} MiB/min over the second half, against "
            f"{s1_min:+.2f} in the first) while {total_drops} record(s) were dropped. "
            f"The ceiling is a queue bound doing its job, not spare capacity."
        )
    elif flat:
        shape = "CONVERGED"
        why = (
            f"RSS levelled off ({s2_min:+.2f} MiB/min over the second half, against "
            f"{s1_min:+.2f} in the first) with nothing dropped. The write path kept up."
        )
    else:
        shape = "STILL RISING"
        why = (
            f"the second half is still climbing at {s2_min:+.2f} MiB/min "
            f"(R^2 {r2:.3f}) after {t[-1]:.0f}s. Nothing in the window bounds it."
        )

    print()
    print(f"  === {meta.get('label')} — {shape} ===")
    print(f"  {why}")
    print()
    print(f"  samples          {len(rows)} over {t[-1]:.0f}s at {meta.get('sample_secs')}s")
    print(f"  RSS  first/peak  {rss[0]:.0f} MiB -> {max(rss):.0f} MiB  (x{max(rss) / rss[0]:.1f})")
    print(f"  slope 1st half   {s1_min:+.2f} MiB/min (R^2 {r1:.3f})")
    print(f"  slope 2nd half   {s2_min:+.2f} MiB/min (R^2 {r2:.3f})")
    if settled_kb is not None:
        settled = settled_kb / 1024.0
        print(f"  after load stops {settled:.0f} MiB  ({settled - max(rss):+.0f} MiB vs peak)")
    print(f"  queue attack_log {q_attack[0]} -> {q_attack[-1]} (max {max(q_attack)}), "
          f"2nd-half slope {qs * 60:+.0f}/min")
    print(f"  queue security_e {q_secev[0]} -> {q_secev[-1]} (max {max(q_secev)})")
    print(f"  pool conns/idle  {rows[-1]['pool_connections']}/{rows[-1]['pool_idle']}")
    print(f"  drops            {drops}")
    print(f"  blocked/allowed  {rows[-1]['requests_blocked']}/{rows[-1]['requests_allowed']}")
    # A queue that drops everything and a batched insert that silently writes
    # nothing produce the same flat RSS curve, and only one of them is a fix. So
    # the rows are counted out of the database rather than inferred from the
    # absence of an error in the log.
    blocked = int(rows[-1]["requests_blocked"])
    written = int(meta.get("rows_security_events", 0)) + int(meta.get("rows_attack_logs", 0))
    if written or blocked:
        share = (written / blocked * 100.0) if blocked else 0.0
        print(f"  rows in DB       {written} of {blocked} blocked ({share:.1f}% recorded)")
    print(f"  load avg         {meta.get('load_before')} -> {meta.get('load_after')}")
    print(f"  tree             {meta.get('tree')} ({meta.get('worktree')})")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
