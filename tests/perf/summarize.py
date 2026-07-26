#!/usr/bin/env python3
"""Aggregate tests/perf/run.sh raw records into a summary JSON + markdown table.

Reads the JSONL emitted by `run.sh` (one record per posture/workload/round) and
reduces the rounds to a single figure per (posture, workload), then computes the
layer attribution deltas.

Why the median and not the mean
-------------------------------
A single round that collided with a background task on the host is an outlier,
not a data point about the WAF, and a mean lets it move the answer. With three
rounds the median discards it structurally. The spread between the best and
worst round is reported alongside every number as `rps_spread_pct`: a figure
whose rounds disagreed by 15% has not measured anything, and the reader is
entitled to see that rather than trust a tidy median.

Why the attribution is a subtraction and not a share
----------------------------------------------------
Each posture is `passthrough` plus one layer, so `posture - passthrough` is that
layer's cost *in the absence of the others*. That is not the same as its cost
inside `full` — detection layers share decoded/normalised inputs, so the parts
do not have to sum to the whole. The summary therefore reports both the
per-layer deltas and the measured `full`, and the gap between their sum and
`full` is printed rather than hidden, because that gap is the interesting part.
"""

from __future__ import annotations

import argparse
import json
import platform
import re
import shutil
import statistics
import subprocess
from pathlib import Path

# Order matters: it is the order the report reads in, coarse to fine.
POSTURE_ORDER = [
    "origin", "passthrough", "lane1",
    "lane1-bot", "lane1-sqli", "lane1-xss", "lane1-scan", "lane1-rce",
    "lane1-sensitive", "lane1-traversal",
    "crs-pl1", "crs-pl2", "crs-pl4",
    "lane2", "cc", "full",
]
WORKLOAD_ORDER = [
    "get-small", "json-post", "form-post", "multipart", "body-1mb", "attack",
]

POSTURE_LABEL = {
    "origin": "origin (no proxy)",
    "passthrough": "passthrough (proxy, no detection)",
    "lane1": "+ Lane 1 regex detectors",
    "lane1-bot": "+ Lane 1: bot only",
    "lane1-sqli": "+ Lane 1: sqli only",
    "lane1-xss": "+ Lane 1: xss only",
    "lane1-scan": "+ Lane 1: scanner only",
    "lane1-rce": "+ Lane 1: rce only",
    "lane1-sensitive": "+ Lane 1: sensitive only",
    "lane1-traversal": "+ Lane 1: traversal only",
    "crs-pl1": "+ OWASP CRS PL1",
    "crs-pl2": "+ OWASP CRS PL2",
    "crs-pl4": "+ OWASP CRS PL4",
    "lane2": "+ Lane 2 semantic (shadow)",
    "cc": "+ rate limiter",
    "full": "full (shipping default)",
}


def cpu_model() -> str:
    try:
        text = Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return platform.processor() or "unknown"
    m = re.search(r"^model name\s*:\s*(.+)$", text, re.MULTILINE)
    return m.group(1).strip() if m else (platform.processor() or "unknown")


def mem_total_gib() -> float:
    try:
        text = Path("/proc/meminfo").read_text(encoding="utf-8")
    except OSError:
        return 0.0
    m = re.search(r"^MemTotal:\s+(\d+) kB$", text, re.MULTILINE)
    return round(int(m.group(1)) / 1024 / 1024, 1) if m else 0.0


def reduce_rounds(records: list[dict]) -> dict:
    """Median by RPS; latency figures come from the SAME round as that median.

    Taking the median of each column independently would synthesise a row that
    no run ever produced — an RPS from one round next to a p99 from another. The
    median round is selected once and reported whole.
    """
    ordered = sorted(records, key=lambda r: r["rps"])
    chosen = ordered[len(ordered) // 2]
    rps_values = [r["rps"] for r in ordered]
    spread = 0.0
    if rps_values and rps_values[-1] > 0:
        spread = (rps_values[-1] - rps_values[0]) / statistics.median(rps_values) * 100

    # CPU microseconds of subject-process time per request, and its median over
    # ALL rounds rather than just the median round.
    #
    # This is the robust figure and the one the layer attribution should be read
    # from. RPS and latency measure "how fast was this host at that moment" —
    # on a shared machine they move with whatever else was running. CPU per
    # request measures "how much work does the WAF do for one request", which is
    # a property of the code. Contention makes each request take longer in wall
    # time without making it cost more CPU cycles, so this number survives a
    # noisy host where RPS does not.
    def per_req(r: dict) -> float | None:
        return (r["cpu_cores"] / r["rps"] * 1e6) if r["rps"] > 0 else None

    cpu_us = [v for v in (per_req(r) for r in ordered) if v is not None]

    return {
        "rps": round(chosen["rps"], 1),
        "p50_ms": round(chosen["p50"] * 1000, 3),
        "p95_ms": round(chosen["p95"] * 1000, 3),
        "p99_ms": round(chosen["p99"] * 1000, 3),
        "p999_ms": round(chosen["p999"] * 1000, 3),
        "max_ms": round(chosen["max"] * 1000, 3),
        "cpu_cores": chosen["cpu_cores"],
        "cpu_us_per_req": round(statistics.median(cpu_us), 2) if cpu_us else None,
        "cpu_us_per_req_spread_pct": (
            round((max(cpu_us) - min(cpu_us)) / statistics.median(cpu_us) * 100, 1)
            if cpu_us and statistics.median(cpu_us) > 0 else None
        ),
        "rss_mib": round(chosen["rss_kb"] / 1024, 1),
        "threads": chosen["threads"],
        "success_rate": chosen["success"],
        "status": chosen["status"],
        "errors": chosen["errors"],
        "requests": chosen["requests"],
        "rounds": len(ordered),
        "rps_spread_pct": round(spread, 1),
    }


def pct(new: float, ref: float) -> float | None:
    """Change of `new` relative to `ref`, in percent. Negative = worse for RPS."""
    if ref in (0, None):
        return None
    return round((new - ref) / ref * 100, 1)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--markdown", required=True)
    ap.add_argument("--duration", type=int, required=True)
    ap.add_argument("--connections", type=int, required=True)
    ap.add_argument("--rounds", type=int, required=True)
    ap.add_argument("--oha", required=True)
    ap.add_argument("--albedo", required=True)
    ap.add_argument("--pin", required=True)
    ap.add_argument("--tree", required=True)
    ap.add_argument("--dirty", required=True)
    ap.add_argument("--load-before", default="")
    ap.add_argument("--load-after", default="")
    # The core sets used to be a hardcoded string in this file, so a run that
    # moved them recorded a pinning it did not use.
    ap.add_argument("--waf-cpus", default="")
    ap.add_argument("--origin-cpus", default="")
    ap.add_argument("--load-cpus", default="")
    # Empty means the shipped default was used, which is a different statement
    # from any particular number and is recorded as such.
    ap.add_argument("--worker-threads", default="")
    ap.add_argument("--lane1-max-body-bytes", default="")
    args = ap.parse_args()

    records: list[dict] = []
    with open(args.raw, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    if not records:
        print("no records in", args.raw)
        return 1

    grouped: dict[tuple[str, str], list[dict]] = {}
    for rec in records:
        grouped.setdefault((rec["posture"], rec["workload"]), []).append(rec)

    postures = [p for p in POSTURE_ORDER if any(k[0] == p for k in grouped)]
    postures += sorted({k[0] for k in grouped} - set(POSTURE_ORDER))
    workloads = [w for w in WORKLOAD_ORDER if any(k[1] == w for k in grouped)]
    workloads += sorted({k[1] for k in grouped} - set(WORKLOAD_ORDER))

    results: dict[str, dict[str, dict]] = {}
    for posture in postures:
        for workload in workloads:
            recs = grouped.get((posture, workload))
            if recs:
                results.setdefault(posture, {})[workload] = reduce_rounds(recs)

    # ── Attribution ─────────────────────────────────────────────────────────
    # Two references, two different questions, both reported per workload:
    #   vs origin      — what an operator pays to put prx-waf in the path
    #   vs passthrough — what the detection layer itself costs
    attribution: dict[str, dict] = {}
    for workload in workloads:
        origin = results.get("origin", {}).get(workload)
        base = results.get("passthrough", {}).get(workload)
        rows = {}
        for posture in postures:
            row = results.get(posture, {}).get(workload)
            if not row:
                continue
            entry = {
                "rps": row["rps"],
                "p99_ms": row["p99_ms"],
                "p999_ms": row["p999_ms"],
                "cpu_us_per_req": row["cpu_us_per_req"],
            }
            if origin:
                entry["rps_vs_origin_pct"] = pct(row["rps"], origin["rps"])
                entry["p99_vs_origin_ms"] = round(row["p99_ms"] - origin["p99_ms"], 3)
            if base and posture not in ("origin", "passthrough"):
                entry["rps_vs_passthrough_pct"] = pct(row["rps"], base["rps"])
                entry["p99_vs_passthrough_ms"] = round(row["p99_ms"] - base["p99_ms"], 3)
                # The layer's own cost, in CPU work rather than wall time. This
                # is the figure to quote when the host was not idle.
                if row["cpu_us_per_req"] and base["cpu_us_per_req"]:
                    entry["cpu_us_vs_passthrough"] = round(
                        row["cpu_us_per_req"] - base["cpu_us_per_req"], 2)
                    entry["cpu_pct_vs_passthrough"] = pct(
                        row["cpu_us_per_req"], base["cpu_us_per_req"])
            rows[posture] = entry

        # Sum-of-parts check. Layers share decoded and normalised inputs, so the
        # parts are not obliged to add up to `full` — and where they do not, the
        # direction of the discrepancy is a real statement about the engine
        # (shared work if the sum overshoots, interaction cost if it undershoots),
        # so it is surfaced rather than quietly dropped.
        full = results.get("full", {}).get(workload)
        if base and full and base["cpu_us_per_req"] and full["cpu_us_per_req"]:
            parts = [
                results[p][workload]["cpu_us_per_req"] - base["cpu_us_per_req"]
                for p in ("lane1", "crs-pl1", "lane2", "cc")
                if p in results and workload in results[p]
                and results[p][workload]["cpu_us_per_req"]
            ]
            if parts:
                rows["_sum_of_parts_check"] = {
                    "sum_of_layer_cpu_us_deltas": round(sum(parts), 2),
                    "measured_full_cpu_us_delta": round(
                        full["cpu_us_per_req"] - base["cpu_us_per_req"], 2),
                }
        attribution[workload] = rows

    summary = {
        "_comment": [
            "prx-waf runtime performance measurement. NOT a CI gate — see README.md.",
            "",
            "Numbers are only comparable against numbers produced by the same",
            "generator version, on the same hardware, at the same connection",
            "count and duration. Restate all four whenever a figure is quoted.",
            "",
            "`recorded_from.tree` is the commit that was BUILT AND MEASURED, and",
            "`recorded_from.worktree_state` says whether that tree had uncommitted",
            "changes. A number measured on a dirty tree is not reproducible and",
            "says so here rather than in a footnote nobody reads.",
        ],
        "recorded_from": {
            "tree": args.tree,
            "worktree_state": args.dirty,
        },
        "environment": {
            "cpu": cpu_model(),
            "cpus": len(__import__("os").sched_getaffinity(0)),
            "memory_gib": mem_total_gib(),
            "kernel": platform.release(),
            "os": " ".join(platform.uname()[:1]) + " " + platform.version(),
            # A shared host is still a legitimate measurement, but it is a
            # different KIND of measurement from an idle one, and the reader has
            # to be able to tell which they are holding.
            "loadavg_1min_at_start": args.load_before,
            "loadavg_1min_at_end": args.load_after,
        },
        "method": {
            "generator": f"oha {args.oha}",
            "origin": f"albedo {args.albedo} (200, empty body — a near-zero-work origin, "
                      f"so the measurement is dominated by the subject and not by the backend)",
            "connections": args.connections,
            "duration_s": args.duration,
            "rounds_per_cell": args.rounds,
            "reduction": "median round by RPS; latency taken from that same round",
            "cpu_pinning": (
                f"on (waf {args.waf_cpus}, origin {args.origin_cpus}, "
                f"generator {args.load_cpus})"
            ) if args.pin == "1" else "off",
            # The two settings whose defaults changed under this harness. Under
            # pinning the shipped worker-thread default follows the WAF's core
            # set, not `nproc`, so the pinning line above is load-bearing for
            # reading it.
            "proxy_worker_threads": (
                args.worker_threads or "shipped default (unset — follows the CPUs the process may use)"
            ),
            "lane1_max_body_bytes": (
                args.lane1_max_body_bytes or "shipped default (65536)"
            ),
            "held_constant": [
                "response cache OFF in every posture (a hit skips the upstream "
                "and would make the WAF measure faster than its own origin)",
                "geoip OFF (no xdb shipped; leaving it on measures a no-op)",
                "audit log OFF",
                "rate limiter, where enabled, is configured never to trigger — "
                "the cost measured is the bucket lookup, not the 429 path",
            ],
        },
        "results": results,
        "attribution": attribution,
    }

    Path(args.out).write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    # ── Markdown ────────────────────────────────────────────────────────────
    md: list[str] = []
    md.append("# prx-waf runtime performance")
    md.append("")
    env = summary["environment"]
    md.append(f"`{env['cpu']}`, {env['cpus']} cpus, {env['memory_gib']} GiB, "
              f"kernel {env['kernel']}")
    md.append(f"oha {args.oha} · albedo {args.albedo} · c={args.connections} · "
              f"{args.duration}s × {args.rounds} rounds · pinning "
              f"{'on' if args.pin == '1' else 'off'}")
    md.append(f"tree `{args.tree[:12]}` ({args.dirty}) · host loadavg "
              f"{args.load_before} → {args.load_after}")
    md.append("")

    for workload in workloads:
        md.append(f"## {workload}")
        md.append("")
        md.append("| posture | RPS | vs origin | p50 | p95 | p99 | p99.9 | CPU µs/req "
                  "| vs base | RSS | RPS spread | µs spread |")
        md.append("|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|")
        origin = results.get("origin", {}).get(workload)
        base = results.get("passthrough", {}).get(workload)
        for posture in postures:
            row = results.get(posture, {}).get(workload)
            if not row:
                continue
            delta = "—"
            if origin and posture != "origin":
                d = pct(row["rps"], origin["rps"])
                delta = f"{d:+.1f}%" if d is not None else "—"
            us = row["cpu_us_per_req"]
            us_s = f"{us:.2f}" if us is not None else "—"
            vs_base = "—"
            if (base and us is not None and base["cpu_us_per_req"]
                    and posture not in ("origin", "passthrough")):
                vs_base = f"{us - base['cpu_us_per_req']:+.2f}"
            us_spread = row["cpu_us_per_req_spread_pct"]
            md.append(
                f"| {POSTURE_LABEL.get(posture, posture)} "
                f"| {row['rps']:,.0f} | {delta} "
                f"| {row['p50_ms']:.2f} | {row['p95_ms']:.2f} | {row['p99_ms']:.2f} "
                f"| {row['p999_ms']:.2f} "
                f"| {us_s} | {vs_base} | {row['rss_mib']:.0f} MiB "
                f"| {row['rps_spread_pct']:.1f}% "
                f"| {us_spread if us_spread is not None else '—'}% |"
            )
        md.append("")
        md.append(
            "Latency in ms. **CPU µs/req** is subject-process CPU time divided by requests "
            "served — read the layer attribution from this column, not from RPS: it measures "
            "work done per request, which is a property of the code, whereas RPS also measures "
            "whatever else the host was doing. `vs base` is µs/req minus the `passthrough` row. "
            "**The `origin` row's µs/req is albedo's CPU, not prx-waf's** — it is a different "
            "program, so compare µs/req only between prx-waf postures; use the RPS column for "
            "the origin comparison. "
            "RSS is the peak seen while sampling at 5 Hz. The two `spread` columns are "
            "(best − worst) over the rounds as a share of the median; treat any figure whose "
            "spread is above ~10% as noise rather than as a result."
        )
        md.append("")

    Path(args.markdown).write_text("\n".join(md) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
