#!/usr/bin/env python3
"""Read an `unmask.sh` sweep and say which of a rule's zeros are masking.

Two numbers per rule, and the gap between them is the whole point.

  priced  corpus rows the rule is NAMED on in the posture its price was taken
          in — the shipped baseline for a default-on rule, which is already
          running, and the shipped baseline plus that one rule for a default-off
          one. This is what `price-rules.py` can see and what both pricing
          documents record.
  solo    corpus rows the rule fires on when every other rule of its own
          detector is switched off. This is what the rule MATCHES.

`solo > priced` means the rule matched rows it was never named on, because a
stronger rule of the same detector took the (detector, view) slot. The rule
costs nothing today and starts costing the moment the rule covering it is
retuned or switched off — which is exactly the reading the `touched` column
exists to support, and exactly what `touched` could not see.

`solo == priced` settles the zero: the rule fires on what it is recorded as
firing on and nothing more.

`solo < priced` should not happen. It would mean the isolated rule lost contact
it has when it runs alongside the others, which no masking model predicts; the
sweep prints it rather than hiding it.

Three rules carry a floor rather than a count, because what hides them is not a
rule and no toggle reaches it:

  * the five `ast.*` structures — `ast.comment_obfusc` replaces the structural
    key on any view that still carried a comment marker, and a `SetOperation`
    body reports `ast.union` or nothing at all;
  * `rce_ast.cmd_subst_any` — the shell-AST walk records it only for a
    substitution whose inner text is NOT dangerous, so a view whose every
    substitution is dangerous can never produce it;
  * `xss.js_exfil` / `xss.js_sink` — they classify the JS contexts the DOM
    detector extracted, so a view the DOM detector declined on budget or size
    carries no context for them to classify.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

# Rules whose solo count is a lower bound. See the module docstring.
FLOORED = {
    "ast.stacked": "ast.comment_obfusc relabel + the SetOperation arm",
    "ast.union": "ast.comment_obfusc relabel",
    "ast.dangerous_fn": "ast.comment_obfusc relabel + the SetOperation arm",
    "ast.tautology": "ast.comment_obfusc relabel + the SetOperation arm",
    "ast.subquery": "ast.comment_obfusc relabel + the SetOperation arm",
    "rce_ast.cmd_subst_any": "the walk's cmd_subst/cmd_subst_any if-else",
    "xss.js_exfil": "no JS context when the DOM detector declines a view",
    "xss.js_sink": "no JS context when the DOM detector declines a view",
}


def load(directory: str, tag: str) -> dict | None:
    path = os.path.join(directory, tag, "report-shadow.json")
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def degraded_count(directory: str, tag: str) -> int | None:
    """How many observation rows ran out of Lane 2 budget.

    Read from the raw observations rather than the report: `classify.py` folds
    `degraded` into its per-case dict but does not serialise it, so the report
    cannot answer this. It matters here because a degraded row stops detection
    early, which understates what an isolated rule matches — the one way this
    sweep could report a false "not masked".
    """
    path = os.path.join(directory, tag, "observations-shadow.json")
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as handle:
        return sum(1 for row in json.load(handle) if row.get("degraded"))


def rows_naming(report: dict, key: str, label: str) -> list[str]:
    return sorted(
        case_id
        for case_id, case in report["cases"].items()
        if case["label"] == label and key in case["rule_keys_fired"]
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dir", required=True, help="the sweep's output directory")
    parser.add_argument("--inventory", help="rules semantic --format json (default: $dir/../inventory.json)")
    parser.add_argument("--json-out", help="write the same data as JSON")
    args = parser.parse_args()

    base = load(args.dir, "baseline")
    if base is None:
        print(f"no baseline run in {args.dir}", file=sys.stderr)
        return 1
    inventory_path = args.inventory or os.path.join(args.dir, os.pardir, "inventory.json")
    with open(inventory_path, encoding="utf-8") as handle:
        inventory = json.load(handle)

    rows = []
    for rule in sorted(inventory, key=lambda r: (r["detector"], -r["confidence"])):
        key = rule["rule_key"]
        solo = load(args.dir, f"solo-{key}")
        # A default-on rule is already named in the baseline; a default-off one
        # needs the run that switched it on by itself.
        priced = base if rule["default_on"] else load(args.dir, f"priced-{key}")
        if solo is None or priced is None:
            continue
        row = {
            "rule_key": key,
            "detector": rule["detector"],
            "confidence": rule["confidence"],
            "default_on": rule["default_on"],
            "floored": FLOORED.get(key),
        }
        for label in ("benign", "attack"):
            row[f"priced_{label}"] = rows_naming(priced, key, label)
            row[f"solo_{label}"] = rows_naming(solo, key, label)
            row[f"hidden_{label}"] = sorted(
                set(row[f"solo_{label}"]) - set(row[f"priced_{label}"])
            )
            row[f"lost_{label}"] = sorted(
                set(row[f"priced_{label}"]) - set(row[f"solo_{label}"])
            )
        row["degraded"] = degraded_count(args.dir, f"solo-{key}")
        rows.append(row)

    base_degraded = degraded_count(args.dir, "baseline")
    worst = max((r["degraded"] or 0) for r in rows) if rows else 0
    print(f"{len(rows)} rules swept; degraded observation rows: baseline "
          f"{base_degraded}, worst solo run {worst}\n")

    header = ("rule", "detector", "conf", "on", "priced", "solo", "hidden", "reading")
    print(f"{header[0]:<34}{header[1]:<13}{header[2]:>5}{header[3]:>4}"
          f"{header[4]:>7}{header[5]:>6}{header[6]:>8}  {header[7]}")
    print(f"{'':<34}{'':<13}{'':>5}{'':>4}{'-- benign rows --':>21}  ")

    masked, clean, lost = [], [], []
    for row in rows:
        named, solo = len(row["priced_benign"]), len(row["solo_benign"])
        hidden = len(row["hidden_benign"])
        if row["lost_benign"]:
            reading = f"LOST {' '.join(row['lost_benign'])} — unexplained"
            lost.append(row)
        elif hidden:
            reading = f"masked on {' '.join(row['hidden_benign'])}"
            masked.append(row)
        else:
            reading = "not masked" + (" (floor)" if row["floored"] else "")
            clean.append(row)
        print(f"{row['rule_key']:<34}{row['detector']:<13}{row['confidence']:>5}"
              f"{('on' if row['default_on'] else 'OFF'):>4}"
              f"{named:>7}{solo:>6}{hidden:>8}  {reading}")

    print(f"\n{len(clean)} rules are named on every benign row they match")
    print(f"{len(masked)} rules match benign rows they are not named on")
    if lost:
        print(f"{len(lost)} rules lost benign contact when isolated — investigate")

    print("\nthe attack half")
    for row in rows:
        if row["hidden_attack"] or row["lost_attack"]:
            parts = []
            if row["hidden_attack"]:
                parts.append(f"masked on {' '.join(row['hidden_attack'])}")
            if row["lost_attack"]:
                parts.append(f"LOST {' '.join(row['lost_attack'])}")
            print(f"  {row['rule_key']}: " + "; ".join(parts))

    print("\nrules whose count is a floor rather than a measurement")
    for row in rows:
        if row["floored"]:
            print(f"  {row['rule_key']}: {row['floored']}")

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as handle:
            json.dump(rows, handle, indent=1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
