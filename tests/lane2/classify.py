#!/usr/bin/env python3
"""Turn a Lane 2 corpus replay into an FP/FN report, split by family and detector.

Two numbers, and neither is meaningful without the other:

  **FN** — of the attack corpus, how much did Lane 2 surface?
  **FP** — of the benign corpus, how much did Lane 2 wrongly flag?

An attack-only measurement always looks good, because "fire more" is free when
nothing counts the cost. A benign-only measurement always looks good, because
"never fire" is free when nothing counts the misses. The pair is the measurement.

Two modes, and the buckets do not mean the same thing in both
=============================================================

`--mode shadow`   The shipped posture: `enforcement_mode = "log_only"`. Verdicts
                  come from the `semantic_observations` rows the lane persists
                  for **every** request that produced at least one signal, joined
                  to the corpus by `client_ip` (see send.py). This is the
                  detection-quality number, and the only one with per-detector
                  and per-rule attribution, because the observation carries the
                  whole signal breakdown.

`--mode enforce`  `enforcement_mode = "enforce"`, `rollout_bps = 10000`. Verdicts
                  come from the HTTP status code. This is the blocking decision —
                  literally the answer to "what happens the day rollout_bps stops
                  being 0", which is the question this harness exists to answer.
                  It has no per-detector attribution (a status code carries none),
                  so shadow mode is where a regression gets diagnosed and enforce
                  mode is where it gets counted.

Attack buckets (shadow), applied in this order
==============================================

  detected          the expected family produced a signal, the request crossed a
                    threshold, and the family that won the roll-up is the
                    expected one — a clean detection
  misattributed     crossed a threshold with an expected-family signal present,
                    but another family won the roll-up. Still detected; the
                    security event names the wrong attack
  sub-threshold     the expected family produced a signal but the request scored
                    below its `log_threshold`, so no security event was written.
                    The cheapest bucket to fix — it is a threshold, not a blind
                    spot — and it is counted as a miss anyway, because an
                    operator watching the event log did not see it
  wrong-family      no expected-family signal, but some other family fired.
                    Detected *something*; the attribution is wrong
  blind             no signal at all. The real detection gap
  harness           the request never reached a verdict (transport error, or the
                    proxy answered before inspection)

Benign buckets (shadow)
=======================

  clean             no signal at all
  sub-threshold     signals fired but the request scored below every threshold.
                    Not an operational false positive today — and one threshold
                    change away from being one, which is why it is reported and
                    not folded into `clean`
  fp-log            a shadow security event was written for benign traffic
  fp-block          the recommendation was **Block**. In the shipped `log_only`
                    posture nothing happened; the moment that family goes to
                    `enforce` and the canary widens, this request is a 403.
                    **This is the number that gates `rollout_bps`.**
  harness           as above

`fp-log` and `fp-block` together are the headline FP count. They are reported
separately because they are not the same risk: one is log noise, the other is an
outage.
"""

from __future__ import annotations

import argparse
import collections
import json
import pathlib
import re
import sys

# The ten families, in the order configs/default.toml declares them, so the
# report reads in the same order as the config an operator is about to edit.
FAMILIES = [
    "sql_injection",
    "rce",
    "traversal",
    "xss",
    "xxe",
    "nosql_injection",
    "ssti",
    "ldap_injection",
    "xpath_injection",
    "deserialization",
]

# `security_events.rule_name` is `format!("{:?} (Semantic)", phase)`
# (scoring.rs). This maps that spelling back to a family, and is only a fallback:
# the primary path derives the family from the winning `rule_id` (= the signal's
# `rule_key`) using the rule_key -> family map the observations themselves carry,
# so the mapping cannot drift from what the engine actually emitted.
PHASE_NAME_TO_FAMILY = {
    "SqlInjection": "sql_injection",
    "Rce": "rce",
    "DirTraversal": "traversal",
    "Xss": "xss",
    "Xxe": "xxe",
    "NoSqlInjection": "nosql_injection",
    "Ssti": "ssti",
    "LdapInjection": "ldap_injection",
    "XpathInjection": "xpath_injection",
    "Deserialization": "deserialization",
}

REC_RANK = {"none": 0, "log": 1, "block": 2}


def semantic_headers(engine_src: str) -> set[str]:
    """The headers Lane 2 actually inspects, read out of the engine source.

    Lane 2's header scope is a **curated list** (`SEMANTIC_HEADERS` in
    `preprocess.rs`), not every header. An attack delivered in, say,
    `X-Api-Key` is therefore never presented to a detector at all — counting it
    as a missed detection would blame the detectors for a surface decision, and
    would make the detection rate move whenever the corpus's header choices
    changed rather than when detection did.

    The list is read from the source rather than transcribed, because a
    transcription silently rots the first time the engine's list changes and the
    report keeps printing a stale scope.
    """
    text = pathlib.Path(engine_src, "crates/waf-engine/src/checks/content_security/preprocess.rs").read_text(
        encoding="utf-8"
    )
    match = re.search(r"const SEMANTIC_HEADERS: &\[&str\] = &\[(.*?)\];", text, re.S)
    if not match:
        raise SystemExit(
            "could not find SEMANTIC_HEADERS in preprocess.rs — the harness cannot "
            "report Lane 2's header scope, and reporting a scope it guessed would be worse"
        )
    # `cookie` is collected separately from the curated list (preprocess.rs
    # handles it as its own field), so it is in scope too.
    return set(re.findall(r'"([^"]+)"', match.group(1))) | {"cookie"}


def load_json(path: str) -> object:
    with pathlib.Path(path).open(encoding="utf-8") as fh:
        return json.load(fh)


def pct(num: int, den: int) -> float:
    return round(100.0 * num / den, 2) if den else 0.0


def build_case_view(results: list[dict], observations: list[dict], events: list[dict]) -> tuple[dict, dict]:
    """Join observations + shadow events onto corpus cases by `client_ip`.

    Returns `(cases, rule_key_to_family)`.
    """
    obs_by_ip: dict[str, list[dict]] = collections.defaultdict(list)
    rule_key_to_family: dict[str, str] = {}
    for row in observations:
        obs_by_ip[row["client_ip"]].append(row)
        for sig in row.get("observations") or []:
            rk, fam = sig.get("rule_key"), sig.get("attack")
            if rk and fam:
                rule_key_to_family[rk] = fam

    ev_by_ip: dict[str, list[dict]] = collections.defaultdict(list)
    for row in events:
        ev_by_ip[row["client_ip"]].append(row)

    cases = {}
    for res in results:
        ip = res["client_ip"]
        rows = obs_by_ip.get(ip, [])
        signals = [s for r in rows for s in (r.get("observations") or [])]
        rec = "none"
        score = 0
        for r in rows:
            if REC_RANK.get(r["recommendation"], 0) > REC_RANK[rec]:
                rec = r["recommendation"]
            score = max(score, int(r["request_score"]))

        # Which family won the roll-up. The security event is the authority
        # (it is what an operator sees); fall back to the observation rows'
        # own recommendation when no event was written.
        primary_family = None
        primary_rule = None
        for ev in ev_by_ip.get(ip, []):
            rid = ev.get("rule_id")
            fam = rule_key_to_family.get(rid) if rid else None
            if fam is None:
                name = (ev.get("rule_name") or "").replace(" (Semantic)", "")
                fam = PHASE_NAME_TO_FAMILY.get(name)
            if fam:
                primary_family, primary_rule = fam, rid
                break

        cases[res["id"]] = {
            **res,
            "n_observations": len(rows),
            "signals": signals,
            "recommendation": rec,
            "request_score": score,
            "families_fired": sorted({s["attack"] for s in signals}),
            "detectors_fired": sorted({s["detector"] for s in signals}),
            "rule_keys_fired": sorted({s["rule_key"] for s in signals}),
            "primary_family": primary_family,
            "primary_rule": primary_rule,
            "degraded": any(r.get("degraded") for r in rows),
        }
    return cases, rule_key_to_family


def bucket_shadow(case: dict) -> str:
    if case["status"] is None or case["status"] == 400:
        return "harness"
    if case["label"] == "attack":
        expected = case["family"]
        has_expected = expected in case["families_fired"]
        crossed = REC_RANK[case["recommendation"]] > 0
        if has_expected and crossed:
            return "detected" if case["primary_family"] == expected else "misattributed"
        if has_expected:
            return "sub-threshold"
        if case["families_fired"]:
            return "wrong-family"
        return "blind"
    # benign
    if case["recommendation"] == "block":
        return "fp-block"
    if case["recommendation"] == "log":
        return "fp-log"
    if case["signals"]:
        return "sub-threshold"
    return "clean"


def bucket_enforce(case: dict) -> str:
    status = case["status"]
    if status is None:
        return "harness"
    if case["label"] == "attack":
        if status == 403:
            return "blocked"
        if status in (200, 404, 405):
            return "not-blocked"
        return "harness"
    if status == 403:
        return "fp-block"
    if status in (200, 404, 405):
        return "passed"
    return "harness"


ATTACK_BUCKETS_SHADOW = ["detected", "misattributed", "sub-threshold", "wrong-family", "blind", "harness"]
BENIGN_BUCKETS_SHADOW = ["clean", "sub-threshold", "fp-log", "fp-block", "harness"]
ATTACK_BUCKETS_ENFORCE = ["blocked", "not-blocked", "harness"]
BENIGN_BUCKETS_ENFORCE = ["passed", "fp-block", "harness"]

# The buckets that count as "Lane 2 surfaced this attack".
DETECTED = {"detected", "misattributed", "blocked"}
# The buckets that count as a false positive on benign traffic.
FALSE_POSITIVE = {"fp-log", "fp-block"}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--results", required=True)
    ap.add_argument("--observations", required=True)
    ap.add_argument("--events", required=True)
    ap.add_argument("--mode", required=True, choices=["shadow", "enforce"])
    ap.add_argument("--engine-src", required=True, help="repo root — Lane 2's header scope is read from it")
    ap.add_argument("--json-out")
    ap.add_argument("--baseline", help="baseline.json; makes the run gate on regressions")
    ap.add_argument("--recorded-from", default="PLACEHOLDER-SHA")
    args = ap.parse_args()

    results = load_json(args.results)["results"]
    observations = load_json(args.observations)
    events = load_json(args.events)

    cases, rule_key_to_family = build_case_view(results, observations, events)
    bucket_of = bucket_shadow if args.mode == "shadow" else bucket_enforce
    for case in cases.values():
        case["bucket"] = bucket_of(case)

    attacks = [c for c in cases.values() if c["label"] == "attack"]
    benign = [c for c in cases.values() if c["label"] == "benign"]

    ab = ATTACK_BUCKETS_SHADOW if args.mode == "shadow" else ATTACK_BUCKETS_ENFORCE
    bb = BENIGN_BUCKETS_SHADOW if args.mode == "shadow" else BENIGN_BUCKETS_ENFORCE

    n_detected = sum(1 for c in attacks if c["bucket"] in DETECTED)
    n_fp = sum(1 for c in benign if c["bucket"] in FALSE_POSITIVE)
    n_fp_block = sum(1 for c in benign if c["bucket"] == "fp-block")

    out = []
    w = out.append
    w("=" * 78)
    w(f"  Lane 2 semantic engine — corpus FP/FN report  ({args.mode} mode)")
    w("=" * 78)
    w("")
    w(f"  attack corpus  {len(attacks):>4}   detected {n_detected:>4}   "
      f"detection rate {pct(n_detected, len(attacks)):>6.2f}%")
    w(f"  benign corpus  {len(benign):>4}   false pos {n_fp:>3}   "
      f"FP rate        {pct(n_fp, len(benign)):>6.2f}%")
    w(f"                             of which would BLOCK {n_fp_block:>3}   "
      f"block-FP rate  {pct(n_fp_block, len(benign)):>6.2f}%")
    w("")

    # ── attack side, by family ────────────────────────────────────────────────
    w("-" * 78)
    w("  ATTACK corpus by family")
    w("-" * 78)
    header = f"  {'family':<18}{'n':>4}{'det':>5}{'rate':>8}   " + "".join(f"{b:>15}" for b in ab)
    w(header)
    per_family_attack = {}
    for fam in FAMILIES:
        rows = [c for c in attacks if c["family"] == fam]
        if not rows:
            continue
        counts = collections.Counter(c["bucket"] for c in rows)
        det = sum(1 for c in rows if c["bucket"] in DETECTED)
        per_family_attack[fam] = {
            "n": len(rows),
            "detected": det,
            "detection_rate": pct(det, len(rows)),
            "buckets": {b: counts.get(b, 0) for b in ab},
        }
        w(f"  {fam:<18}{len(rows):>4}{det:>5}{pct(det, len(rows)):>7.1f}%   "
          + "".join(f"{counts.get(b, 0):>15}" for b in ab))
    w("")

    # ── attack side, by difficulty ────────────────────────────────────────────
    per_difficulty = {}
    w(f"  {'difficulty':<18}{'n':>4}{'det':>5}{'rate':>8}")
    for diff in ["canonical", "evasive", "hard"]:
        rows = [c for c in attacks if c.get("difficulty") == diff]
        if not rows:
            continue
        det = sum(1 for c in rows if c["bucket"] in DETECTED)
        per_difficulty[diff] = {"n": len(rows), "detected": det, "detection_rate": pct(det, len(rows))}
        w(f"  {diff:<18}{len(rows):>4}{det:>5}{pct(det, len(rows)):>7.1f}%")
    w("")

    # ── benign side, by the family that fired ─────────────────────────────────
    w("-" * 78)
    w("  BENIGN corpus — which family produced the noise")
    w("-" * 78)
    w(f"  {'family':<18}{'any signal':>12}{'fp-log':>9}{'fp-block':>10}   (of "
      f"{len(benign)} benign requests)")
    per_family_benign = {}
    for fam in FAMILIES:
        any_sig = sum(1 for c in benign if fam in c["families_fired"])
        fp_log = sum(1 for c in benign if c["bucket"] == "fp-log" and c["primary_family"] == fam)
        fp_blk = sum(1 for c in benign if c["bucket"] == "fp-block" and fam in c["families_fired"])
        if any_sig == 0 and fp_log == 0 and fp_blk == 0:
            continue
        per_family_benign[fam] = {"any_signal": any_sig, "fp_log": fp_log, "fp_block": fp_blk}
        w(f"  {fam:<18}{any_sig:>12}{fp_log:>9}{fp_blk:>10}")
    if not per_family_benign:
        w("  (no family produced a single signal on the benign corpus)")
    w("")

    # ── per-detector and per-rule attribution ─────────────────────────────────
    if args.mode == "shadow":
        w("-" * 78)
        w("  DETECTOR attribution")
        w("-" * 78)
        w(f"  {'detector':<16}{'attack hits':>13}{'benign hits':>13}   "
          f"{'benign cases':>13}")
        det_attack = collections.Counter()
        det_benign = collections.Counter()
        det_benign_cases = collections.Counter()
        for c in attacks:
            for d in c["detectors_fired"]:
                det_attack[d] += 1
        for c in benign:
            for d in c["detectors_fired"]:
                det_benign[d] += 1
                det_benign_cases[d] += 1
        per_detector = {}
        for d in sorted(set(det_attack) | set(det_benign)):
            per_detector[d] = {"attack_cases": det_attack[d], "benign_cases": det_benign[d]}
            w(f"  {d:<16}{det_attack[d]:>13}{det_benign[d]:>13}{det_benign_cases[d]:>13}")
        if not per_detector:
            w("  (no detector fired at all — check the harness before believing this)")
        w("")

        w("-" * 78)
        w("  RULE attribution on BENIGN traffic — the false-positive sources")
        w("-" * 78)
        rule_benign = collections.Counter()
        for c in benign:
            for rk in c["rule_keys_fired"]:
                rule_benign[rk] += 1
        per_rule_benign = {}
        if rule_benign:
            w(f"  {'rule_key':<34}{'family':<18}{'benign cases':>13}")
            for rk, n in rule_benign.most_common():
                fam = rule_key_to_family.get(rk, "?")
                per_rule_benign[rk] = {"family": fam, "benign_cases": n}
                w(f"  {rk:<34}{fam:<18}{n:>13}")
        else:
            w("  (no rule fired on benign traffic)")
        w("")

        w("-" * 78)
        w("  RULE attribution on ATTACK traffic")
        w("-" * 78)
        rule_attack = collections.Counter()
        for c in attacks:
            for rk in c["rule_keys_fired"]:
                rule_attack[rk] += 1
        per_rule_attack = {}
        if rule_attack:
            w(f"  {'rule_key':<34}{'family':<18}{'attack cases':>13}")
            for rk, n in rule_attack.most_common():
                fam = rule_key_to_family.get(rk, "?")
                per_rule_attack[rk] = {"family": fam, "attack_cases": n}
                w(f"  {rk:<34}{fam:<18}{n:>13}")
        else:
            w("  (no rule fired on attack traffic)")
        w("")
    else:
        per_detector = {}
        per_rule_benign = {}
        per_rule_attack = {}

    # ── the individual failures, named ────────────────────────────────────────
    w("-" * 78)
    w("  FALSE POSITIVES, named")
    w("-" * 78)
    fps = [c for c in benign if c["bucket"] in FALSE_POSITIVE]
    if fps:
        for c in sorted(fps, key=lambda c: (c["bucket"], c["id"])):
            rules = ",".join(c["rule_keys_fired"]) or "-"
            w(f"  [{c['bucket']:>8}] {c['id']:<18} score={c['request_score']:>3} "
              f"trap={c.get('trap') or '-'}")
            w(f"             {c['note']}")
            w(f"             rules: {rules}")
    else:
        w("  (none)")
    w("")

    # ── surfaces Lane 2 never looks at ────────────────────────────────────────
    # Advisory, not a bucket. Reclassifying these automatically would need the
    # corpus to declare *which* field carries the payload, which it does not, and
    # a guess that reclassified a row wrongly would inflate the detection rate.
    # So they are named and counted, and the reader subtracts.
    in_scope = semantic_headers(args.engine_src)
    off_surface = [
        c
        for c in attacks
        if not c.get("has_query")
        and not c.get("has_body")
        and [h for h in (c.get("header_names") or []) if h.lower() not in in_scope]
    ]
    w("-" * 78)
    w("  ATTACK rows delivered on a surface Lane 2 does not inspect")
    w("-" * 78)
    w(f"  Lane 2's header scope (preprocess.rs SEMANTIC_HEADERS + cookie): "
      f"{', '.join(sorted(in_scope))}")
    if off_surface:
        w(f"  {len(off_surface)} attack rows carry no query and no body, and every header they")
        w("  do carry is outside that scope. A miss here is a surface decision, not a")
        w("  detector defect — read the detection rate with these subtracted:")
        for c in sorted(off_surface, key=lambda c: c["id"]):
            outside = ",".join(h for h in c["header_names"] if h.lower() not in in_scope)
            w(f"    {c['id']:<16} {c['family']:<18} bucket={c['bucket']:<14} headers={outside}")
        n_off_missed = sum(1 for c in off_surface if c["bucket"] not in DETECTED)
        adj_n = len(attacks) - n_off_missed
        w(f"  detection rate excluding the {n_off_missed} out-of-scope misses: "
          f"{pct(n_detected, adj_n):.2f}% ({n_detected}/{adj_n})")
    else:
        w("  (every attack row lands on a surface Lane 2 inspects)")
    w("")

    w("-" * 78)
    w("  MISSED ATTACKS, named")
    w("-" * 78)
    misses = [c for c in attacks if c["bucket"] not in DETECTED]
    if misses:
        for c in sorted(misses, key=lambda c: (c["family"] or "", c["bucket"], c["id"])):
            other = ",".join(c["families_fired"]) or "-"
            w(f"  [{c['bucket']:>13}] {c['id']:<16} {c['family']:<18} "
              f"{c.get('difficulty') or '-':<10} score={c['request_score']:>3} fired={other}")
            w(f"                  {c['note']}")
    else:
        w("  (none)")
    w("")

    report = {
        "mode": args.mode,
        "recorded_from": args.recorded_from,
        "totals": {
            "attack": {
                "n": len(attacks),
                "detected": n_detected,
                "detection_rate": pct(n_detected, len(attacks)),
                "buckets": {b: sum(1 for c in attacks if c["bucket"] == b) for b in ab},
            },
            "benign": {
                "n": len(benign),
                "false_positives": n_fp,
                "fp_rate": pct(n_fp, len(benign)),
                "fp_block": n_fp_block,
                "fp_block_rate": pct(n_fp_block, len(benign)),
                "buckets": {b: sum(1 for c in benign if c["bucket"] == b) for b in bb},
            },
        },
        "lane2_header_scope": sorted(in_scope),
        "attacks_off_surface": sorted(c["id"] for c in off_surface),
        "by_family_attack": per_family_attack,
        "by_family_benign": per_family_benign,
        "by_difficulty": per_difficulty,
        "by_detector": per_detector,
        "by_rule_benign": per_rule_benign,
        "by_rule_attack": per_rule_attack,
        "cases": {
            cid: {
                "bucket": c["bucket"],
                "label": c["label"],
                "family": c["family"],
                "difficulty": c.get("difficulty"),
                "trap": c.get("trap"),
                "status": c["status"],
                "recommendation": c["recommendation"],
                "request_score": c["request_score"],
                "families_fired": c["families_fired"],
                "rule_keys_fired": c["rule_keys_fired"],
                "primary_family": c["primary_family"],
            }
            for cid, c in sorted(cases.items())
        },
    }

    text = "\n".join(out)
    print(text)
    if args.json_out:
        with pathlib.Path(args.json_out).open("w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=1, sort_keys=True)

    # ── gate ──────────────────────────────────────────────────────────────────
    if not args.baseline:
        return 0
    baseline = load_json(args.baseline)
    recorded = (baseline.get("modes") or {}).get(args.mode)
    if not recorded:
        print(f"\nBASELINE: no '{args.mode}' entry in {args.baseline} — nothing to gate on", file=sys.stderr)
        return 0

    failures = []
    exp = recorded["attack"]
    if n_detected < exp["detected"]:
        failures.append(
            f"attack detections regressed: {n_detected} < baseline {exp['detected']}"
        )
    exp = recorded["benign"]
    if n_fp > exp["false_positives"]:
        failures.append(
            f"false positives regressed: {n_fp} > baseline {exp['false_positives']}"
        )
    if n_fp_block > exp["fp_block"]:
        failures.append(
            f"blocking false positives regressed: {n_fp_block} > baseline {exp['fp_block']}"
        )
    # A corpus that shrank would make every count above look better for free.
    if len(attacks) < recorded["attack"]["n"] or len(benign) < recorded["benign"]["n"]:
        failures.append(
            f"corpus shrank: attack {len(attacks)} (baseline {recorded['attack']['n']}), "
            f"benign {len(benign)} (baseline {recorded['benign']['n']})"
        )

    print("-" * 78)
    if failures:
        print(f"  GATE FAILED ({args.mode} mode)")
        for f in failures:
            print(f"    * {f}")
        return 1
    print(f"  GATE PASSED ({args.mode} mode) — "
          f"detected {n_detected} >= {recorded['attack']['detected']}, "
          f"FP {n_fp} <= {recorded['benign']['false_positives']}, "
          f"block-FP {n_fp_block} <= {recorded['benign']['fp_block']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
