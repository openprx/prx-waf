#!/usr/bin/env python3
"""Generate the blocking-mode status expectations the CRS corpus does not carry.

CLOUD MODE ONLY. `run.sh` does not call this in log mode, and it must not: log
mode reads the corpus's own `expect_ids` / `no_expect_ids` assertions out of
prx-waf's audit log, which is the whole reason log mode exists. Rewriting them
into status codes there would throw away the fidelity the mode was added for.

WHY THIS EXISTS — read before touching anything here.

The CRS regression corpus is written against a reference stack that runs
ModSecurity in `SecRuleEngine DetectionOnly` (see coreruleset
tests/docker-compose.yml: `MODSEC_RULE_ENGINE: DetectionOnly`). Nothing is ever
blocked there, so the assertions are all about the *audit log*:

    output:
      log:
        expect_ids: [942100]

and almost no test carries an `output.status`.

go-ftw's cloud mode decides purely from the HTTP status code, and its
`AssertStatus` short-circuits:

    if c.expected.Status == 0 { return true }      # check/status.go

With no `status` in the test and no log to read in cloud mode, *every* check
returns true. A naive `go-ftw run --cloud` against this corpus therefore reports
~100% and means absolutely nothing. That is a trap, not a result.

This script closes the gap the only way that keeps the corpus intact: it emits a
go-ftw platform-overrides file (`--overrides`, the same mechanism CRS ships
`coraza-overrides.yaml` and `nginx-overrides.yaml` through) that restates each
existing assertion as its blocking-mode equivalent:

    log.expect_ids / log.match_regex        (rule must fire)      -> status 403
    log.no_expect_ids / log.no_match_regex  (rule must not fire)  -> status 200

Nothing else is touched. In particular:

  * The original `log:` block is copied through verbatim, so the file stays a
    faithful restatement rather than a rewrite.
  * A stage that already declares its own `status` is left alone — that status
    is the test author's explicit expectation and overriding it would be
    exactly the kind of scope tampering this harness must not do.
  * A stage that asserts `expect_error` is left alone; go-ftw checks that before
    it ever looks at a status.
  * No test is dropped, no rule is skipped, no id is filtered.

The 403/200 mapping is the same one go-ftw's own cloud mode uses when a status
*is* present (`assertCloudStatus`: expect_ids + 403 passes, no_expect_ids +
{200,404,405} passes), so this only supplies the missing operand, it does not
invent a new verdict rule.
"""

from __future__ import annotations

import argparse
import glob
import os
import sys

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("PyYAML required: pip install pyyaml")


BLOCK_STATUS = 403
PASS_STATUS = 200


def build(crs_dir: str) -> tuple[dict, dict]:
    root = os.path.join(crs_dir, "tests", "regression", "tests")
    overrides: list[dict] = []
    counts = {"block": 0, "pass": 0, "kept-own-status": 0, "no-assertion": 0, "stages": 0}

    for path in sorted(glob.glob(os.path.join(root, "**", "*.yaml"), recursive=True)):
        with open(path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        if not isinstance(doc, dict) or "tests" not in doc:
            continue
        rule_id = doc.get("rule_id")
        for case in doc.get("tests") or []:
            for index, stage in enumerate(case.get("stages") or []):
                counts["stages"] += 1
                out = dict(stage.get("output") or {})
                log = out.get("log") or {}

                if out.get("status") is not None:
                    counts["kept-own-status"] += 1
                    continue
                if out.get("expect_error") is not None:
                    counts["no-assertion"] += 1
                    continue

                fires = bool(log.get("expect_ids") or log.get("match_regex")
                             or out.get("log_contains"))
                quiet = bool(log.get("no_expect_ids") or log.get("no_match_regex")
                             or out.get("no_log_contains"))

                if fires:
                    status, reason, key = BLOCK_STATUS, "rule must fire", "block"
                elif quiet:
                    status, reason, key = PASS_STATUS, "rule must not fire", "pass"
                else:
                    counts["no-assertion"] += 1
                    continue

                counts[key] += 1
                new_out = dict(out)
                new_out["status"] = status
                overrides.append({
                    "rule_id": int(rule_id),
                    "test_ids": [int(case["test_id"])],
                    "stage_ids": [index],
                    "reason": (
                        f"blocking-mode restatement: the CRS corpus asserts on the "
                        f"DetectionOnly audit log ({reason}); prx-waf runs in blocking "
                        f"mode, where the equivalent observable is HTTP {status}"
                    ),
                    "output": new_out,
                })

    document = {
        "version": "v0.0.0",
        "meta": {
            "engine": "prx-waf",
            "platform": "pingora",
            "annotations": {
                "purpose": "restate log assertions as blocking-mode status codes",
                "generated-by": "tests/ftw/gen_overrides.py",
            },
        },
        "test_overrides": overrides,
    }
    return document, counts


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--crs", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    document, counts = build(args.crs)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write("# Generated by tests/ftw/gen_overrides.py — do not edit, do not commit.\n")
        fh.write("# Restates each CRS log assertion as its blocking-mode status code.\n")
        yaml.safe_dump(document, fh, sort_keys=False, width=200)

    print(
        f"overrides: {len(document['test_overrides'])} stage(s) "
        f"[must-block={counts['block']} must-pass={counts['pass']}] "
        f"of {counts['stages']} total; "
        f"{counts['kept-own-status']} kept their own status, "
        f"{counts['no-assertion']} assert neither",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
