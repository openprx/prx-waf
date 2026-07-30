#!/usr/bin/env python3
"""Read a `price-rules.sh` sweep and print what each rule costs.

Every experiment directory holds the two reports `classify.py` wrote for one
rule; `baseline/` holds the same two with nothing switched on. The bill for a
rule is the difference, and it has two halves that must be read together:

  * the attack half — corpus rows the rule moved into `detected` (shadow) or
    `blocked` (enforce);
  * the benign half — corpus rows it moved into `fp-log` or `fp-block`.

The second is why the rules ship off. A rule that recovers three attacks and
flags three benign requests has not earned its place, and a rule that produces
one `fp-block` has cost more than any detection it brought, because `fp-block`
is the number that gates `rollout_bps`.

`benign sub-thr` is the third number to read: benign rows that started scoring
but stayed under every threshold. They are not false positives today and they
are one threshold change away from being some, so a rule that moves nothing but
that column is not free — it is a rule whose cost is deferred.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

ATTACK_HIT = {"detected", "misattributed"}
BENIGN_FP = {"fp-log", "fp-block"}


def load(directory: str, tag: str, mode: str) -> dict | None:
    path = os.path.join(directory, tag, f"report-{mode}.json")
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def moved_into(new: dict, old: dict, label: str, buckets: set[str]) -> list[str]:
    """Corpus rows that are in `buckets` now and were not before."""
    return sorted(
        case_id
        for case_id, case in new.items()
        if case["label"] == label
        and case["bucket"] in buckets
        and case_id in old
        and old[case_id]["bucket"] not in buckets
    )


def price(directory: str, tag: str, base: dict[str, dict]) -> dict | None:
    shadow, enforce = load(directory, tag, "shadow"), load(directory, tag, "enforce")
    if shadow is None or enforce is None:
        return None
    totals, base_totals = shadow["totals"], base["shadow"]["totals"]
    en_totals, base_en_totals = enforce["totals"], base["enforce"]["totals"]
    cases, base_cases = shadow["cases"], base["shadow"]["cases"]
    en_cases, base_en_cases = enforce["cases"], base["enforce"]["cases"]

    def sub(new: dict, old: dict, *path: str) -> int:
        for key in path:
            new, old = new[key], old[key]
        return new - old

    return {
        "tag": tag,
        "detected": sub(totals, base_totals, "attack", "detected"),
        "fp": sub(totals, base_totals, "benign", "false_positives"),
        "fp_block_shadow": sub(totals, base_totals, "benign", "fp_block"),
        "blocked": sub(en_totals, base_en_totals, "attack", "detected"),
        "fp_block_enforce": sub(en_totals, base_en_totals, "benign", "fp_block"),
        "benign_sub": (
            totals["benign"]["buckets"].get("sub-threshold", 0)
            - base_totals["benign"]["buckets"].get("sub-threshold", 0)
        ),
        "attacks_gained": moved_into(cases, base_cases, "attack", ATTACK_HIT),
        "attacks_lost": moved_into(base_cases, cases, "attack", ATTACK_HIT),
        "fp_gained": moved_into(cases, base_cases, "benign", BENIGN_FP),
        "fp_lost": moved_into(base_cases, cases, "benign", BENIGN_FP),
        "blocks_gained": moved_into(en_cases, base_en_cases, "attack", {"blocked"}),
        "fp_blocks_gained": moved_into(en_cases, base_en_cases, "benign", {"fp-block"}),
    }


def verdict(row: dict) -> str:
    """The default reading of one rule's bill.

    Deliberately mechanical and deliberately not the last word: it knows the
    corpus and not the deployment, so a rule it calls noisy may be exactly right
    on a route that never carries the shape it fires on. It is a first pass over
    thirty-eight rows, not a recommendation.
    """
    if row["fp_block_enforce"] > 0 or row["fp_block_shadow"] > 0:
        return "keep off — produces a blocking false positive"
    if row["detected"] <= 0 and row["fp"] <= 0:
        if row["benign_sub"] > 0:
            return "no effect on this corpus, but starts scoring benign rows"
        return "no effect on this corpus"
    if row["detected"] > 0 and row["fp"] == 0:
        return "turn on — recovers attacks at no measured cost"
    if row["detected"] > row["fp"]:
        return "conditional — recovers more than it costs, but it does cost"
    return "keep off — costs at least as much as it recovers"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dir", required=True, help="the sweep's output directory")
    parser.add_argument("--json-out", help="write the same data as JSON")
    args = parser.parse_args()

    base = {mode: load(args.dir, "baseline", mode) for mode in ("shadow", "enforce")}
    if not all(base.values()):
        print(f"no baseline run in {args.dir}", file=sys.stderr)
        return 1

    tags = sorted(
        entry for entry in os.listdir(args.dir)
        if entry != "baseline" and os.path.isdir(os.path.join(args.dir, entry))
    )
    rows = [row for row in (price(args.dir, tag, base) for tag in tags) if row]

    bs, be = base["shadow"]["totals"], base["enforce"]["totals"]
    print(
        f"baseline: shadow {bs['attack']['detected']}/{bs['benign']['false_positives']}"
        f"/{bs['benign']['fp_block']}   enforce {be['attack']['detected']}"
        f"/{be['benign']['false_positives']}/{be['benign']['fp_block']}\n"
    )
    header = ("rule", "det", "FP", "FPblk", "blocked", "FPblk", "sub-thr", "reading")
    print(f"{header[0]:<34}{header[1]:>5}{header[2]:>5}{header[3]:>6}"
          f"{header[4]:>9}{header[5]:>6}{header[6]:>9}  {header[7]}")
    print(f"{'':<34}{'--- shadow ---':>16}{'-- enforce --':>15}")
    for row in rows:
        print(f"{row['tag']:<34}{row['detected']:>+5}{row['fp']:>+5}"
              f"{row['fp_block_shadow']:>+6}{row['blocked']:>+9}"
              f"{row['fp_block_enforce']:>+6}{row['benign_sub']:>+9}  {verdict(row)}")

    print("\nper-case movement")
    for row in rows:
        parts = [
            f"{name} {' '.join(row[field])}"
            for name, field in (
                ("attacks+", "attacks_gained"), ("attacks-", "attacks_lost"),
                ("fp+", "fp_gained"), ("fp-", "fp_lost"),
                ("blocked+", "blocks_gained"), ("fp-block+", "fp_blocks_gained"),
            )
            if row[field]
        ]
        print(f"  {row['tag']}: " + ("; ".join(parts) if parts else "nothing moved"))

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as handle:
            json.dump(rows, handle, indent=1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
