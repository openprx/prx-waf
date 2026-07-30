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

`benign touched` is the fourth, and it is the widest of them. A bucket only
changes when the row crosses a threshold, so bucket deltas cannot see a rule
that fires on twenty benign rows and pushes none of them over — yet that rule is
the one that will produce false positives the moment a threshold, a weight or a
corroborating rule moves. So this counts benign rows on which the run fired any
rule the baseline did not, whatever bucket they ended in. It is the rule's
contact with benign traffic, and a rule with a large touch count and a zero FP
count has not been shown to be safe; it has been shown to be one change away.

Both directions
===============

`--direction enable` (the default) reads a sweep that switched one default-OFF
rule on: the baseline is the shipped tree, the experiment is the tree plus one
rule, and the bill is what the rule would add.

`--direction disable` reads a sweep that switched one default-ON rule off: the
baseline is still the shipped tree, but now it is the experiment that is missing
a rule, so the arithmetic runs the other way — the bill is what the tree LOSES
when the rule goes, which is the same thing as what the rule is contributing
today. Every column keeps its meaning: `det` is still detections the rule is
responsible for, `FP` is still false positives it is responsible for, `touched`
is still the benign rows it fires on. Only the subtraction is reversed.

That reversal is the whole point. The `touched` column was invented for rules
nobody had ever run, and it answered a question about the future. Pointed the
other way it answers a question about the present: of the rules that ARE running,
which ones are sitting on a pile of benign traffic and are held off the false
positive list by nothing but the distance to a threshold. Those never show up in
the FP count, the fp-block count or any bucket delta, because in the shipped
posture they are already on and already not crossing. `touched over thr` is the
matching column for that reading — of the benign rows a rule fires on, how many
are over a threshold in the posture where the rule is on. `touched` minus that
is the latent pile.
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


def touched(new: dict, old: dict, label: str) -> list[str]:
    """Rows on which the run fired a rule the baseline did not, any bucket.

    Derived from the fired-rule sets rather than from the rule key under test,
    so it reads a combination run the same way it reads a single-rule one.
    """
    out = []
    for case_id, case in new.items():
        if case["label"] != label or case_id not in old:
            continue
        gained = set(case["rule_keys_fired"]) - set(old[case_id]["rule_keys_fired"])
        if gained:
            out.append(case_id)
    return sorted(out)


def price(directory: str, tag: str, base: dict[str, dict], direction: str) -> dict | None:
    shadow, enforce = load(directory, tag, "shadow"), load(directory, tag, "enforce")
    if shadow is None or enforce is None:
        return None
    run = {"shadow": shadow, "enforce": enforce}
    # `new` is always the side of the comparison on which the rule under test is
    # RUNNING, whichever direction the sweep switched it. Every column below then
    # keeps one meaning across both sweeps: what the rule does when it is on.
    new, old = (run, base) if direction == "enable" else (base, run)
    totals, base_totals = new["shadow"]["totals"], old["shadow"]["totals"]
    en_totals, base_en_totals = new["enforce"]["totals"], old["enforce"]["totals"]
    cases, base_cases = new["shadow"]["cases"], old["shadow"]["cases"]
    en_cases, base_en_cases = new["enforce"]["cases"], old["enforce"]["cases"]

    def sub(new: dict, old: dict, *path: str) -> int:
        for key in path:
            new, old = new[key], old[key]
        return new - old

    benign_touched = touched(cases, base_cases, "benign")
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
        "benign_touched": benign_touched,
        # Of the benign rows the rule fires on, the ones that are over a
        # threshold in the posture where it is on. `benign_touched` minus this
        # is the rule's latent pile: contact with benign traffic that no bucket,
        # no FP count and no delta in this table can see.
        "benign_touched_over": [
            case_id for case_id in benign_touched
            if case_id in cases and cases[case_id]["bucket"] in BENIGN_FP
        ],
        "attacks_touched": touched(cases, base_cases, "attack"),
        "attacks_gained": moved_into(cases, base_cases, "attack", ATTACK_HIT),
        "attacks_lost": moved_into(base_cases, cases, "attack", ATTACK_HIT),
        "fp_gained": moved_into(cases, base_cases, "benign", BENIGN_FP),
        "fp_lost": moved_into(base_cases, cases, "benign", BENIGN_FP),
        "blocks_gained": moved_into(en_cases, base_en_cases, "attack", {"blocked"}),
        "fp_blocks_gained": moved_into(en_cases, base_en_cases, "benign", {"fp-block"}),
    }


def verdict_off(row: dict) -> str:
    """The default reading of one already-running rule's contribution.

    The disable sweep asks a different question from the enable sweep, so it gets
    a different sentence. Nothing here is a recommendation to switch a rule off:
    the corpus is 220 benign rows and a deployment is not, and a rule that looks
    idle on this corpus may be the only thing standing between a route and the
    shape it was written for. What this can say is which running rules are
    carrying detection, which are producing today's false positives, and which
    are sitting on benign traffic without having crossed anything yet.
    """
    latent = len(row["benign_touched"]) - len(row["benign_touched_over"])
    if row["fp"] > 0 or row["fp_block_shadow"] > 0 or row["fp_block_enforce"] > 0:
        return (
            f"already producing false positives — {row['fp']} FP, "
            f"{row['fp_block_shadow']} of them blocking, for {row['detected']} detections"
        )
    if latent >= 10:
        return f"latent pressure — fires on {latent} benign rows, crosses nothing"
    if latent > 0:
        return f"low latent pressure — {latent} benign rows under the line"
    if row["detected"] > 0 or row["blocked"] > 0:
        return "clean — carries detection, no benign contact"
    return "clean — no benign contact, and nothing moves on this corpus either"


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
        if row["benign_sub"] > 0 or row["benign_touched"]:
            return "no effect on this corpus, but starts scoring benign rows"
        return "no effect on this corpus"
    if row["detected"] > 0 and row["fp"] == 0:
        if len(row["benign_touched"]) > row["detected"]:
            return "turn on with a holdout — no FP here, but it touches benign rows"
        return "turn on — recovers attacks at no measured cost"
    if row["detected"] > row["fp"]:
        return "conditional — recovers more than it costs, but it does cost"
    return "keep off — costs at least as much as it recovers"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dir", required=True, help="the sweep's output directory")
    parser.add_argument("--json-out", help="write the same data as JSON")
    parser.add_argument(
        "--direction", choices=("enable", "disable"), default="enable",
        help="which way the sweep switched each rule; `disable` reverses the "
             "subtraction so the columns still read as what the rule does when on",
    )
    args = parser.parse_args()

    base = {mode: load(args.dir, "baseline", mode) for mode in ("shadow", "enforce")}
    if not all(base.values()):
        print(f"no baseline run in {args.dir}", file=sys.stderr)
        return 1

    tags = sorted(
        entry for entry in os.listdir(args.dir)
        if entry != "baseline" and os.path.isdir(os.path.join(args.dir, entry))
    )
    rows = [
        row for row in (price(args.dir, tag, base, args.direction) for tag in tags) if row
    ]

    bs, be = base["shadow"]["totals"], base["enforce"]["totals"]
    print(
        f"baseline: shadow {bs['attack']['detected']}/{bs['benign']['false_positives']}"
        f"/{bs['benign']['fp_block']}   enforce {be['attack']['detected']}"
        f"/{be['benign']['false_positives']}/{be['benign']['fp_block']}"
        f"   ({args.direction} sweep)\n"
    )
    header = ("rule", "det", "FP", "FPblk", "blocked", "FPblk",
              "sub-thr", "touched", "over", "reading")
    print(f"{header[0]:<34}{header[1]:>5}{header[2]:>5}{header[3]:>6}"
          f"{header[4]:>9}{header[5]:>6}{header[6]:>9}{header[7]:>9}"
          f"{header[8]:>6}  {header[9]}")
    print(f"{'':<34}{'--- shadow ---':>16}{'-- enforce --':>15}"
          f"{'------ benign ------':>24}")
    read = verdict if args.direction == "enable" else verdict_off
    for row in rows:
        print(f"{row['tag']:<34}{row['detected']:>+5}{row['fp']:>+5}"
              f"{row['fp_block_shadow']:>+6}{row['blocked']:>+9}"
              f"{row['fp_block_enforce']:>+6}{row['benign_sub']:>+9}"
              f"{len(row['benign_touched']):>9}"
              f"{len(row['benign_touched_over']):>6}  {read(row)}")

    print("\nper-case movement")
    for row in rows:
        parts = [
            f"{name} {' '.join(row[field])}"
            for name, field in (
                ("attacks+", "attacks_gained"), ("attacks-", "attacks_lost"),
                ("fp+", "fp_gained"), ("fp-", "fp_lost"),
                ("blocked+", "blocks_gained"), ("fp-block+", "fp_blocks_gained"),
                ("benign-touched", "benign_touched"),
                ("benign-touched-over-thr", "benign_touched_over"),
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
