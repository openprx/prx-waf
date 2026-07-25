#!/usr/bin/env python3
"""Turn a go-ftw run into a classified pass/fail report.

A bare pass rate says "63%" and stops there. What the project actually needs to
know is *why* the other 37% failed, because three of the reasons are known
structural gaps in the engine and only the fourth is a detection-quality defect.
This script splits the failures into those groups so a later change can be
measured against the group it was supposed to move.

Two modes, and the buckets do not mean the same thing in both
============================================================

`--mode cloud`  go-ftw judged every test by its HTTP status code. A negative
                test can then only assert "nothing blocked", so any CRS rule
                blocking the request fails it — including one the corpus never
                mentions. That is the `over-block`/`collateral` split below, and
                it is an artefact of the mode, not of the rule set.

`--mode log`    go-ftw judged every test by the rule ids prx-waf wrote to its
                audit log, with the WAF in DetectionOnly. A negative test now
                asserts exactly what the corpus says — "rule X did not fire" —
                so `collateral` cannot occur by construction and every
                `over-block` entry is a genuine false positive of the rule under
                test. This is the posture ModSecurity v2 + CRS and Coraza are
                measured in.

In log mode the firing rules come from go-ftw itself (`triggered-rules` in its
JSON output, one list per stage — runner/stats.go), so attribution needs no
replay and is exact rather than inferred from a block page.

Buckets, applied to every FAILED test in this order:

  not-implemented   The rule the test targets does not exist in
                    rules/owasp-crs/ at all. Sub-reason comes from the upstream
                    SecRule: response phase, FILES, MULTIPART_PART_HEADERS,
                    header-count (&REQUEST_HEADERS:...), TX sentinel, other.
  paranoia-scope    The rule exists but declares a paranoia level above the one
                    this run enabled, so it was never evaluated. Not a defect —
                    the same test fails on ModSecurity at that PL too.
  over-block        A *negative* test (CRS asserts the rule must NOT fire) that
                    the WAF got wrong. In log mode that is always the rule under
                    test firing on a payload it must not match. In cloud mode it
                    is "the request was blocked", which with --replay splits
                    further, because the two halves have completely different
                    owners:

                      same-rule   the rule under test is the one that fired.
                                  A genuine false positive of that rule — the
                                  converted pattern is broader than upstream's.
                      collateral  a *different* CRS rule fired. Upstream logs
                                  that rule too and the test does not care,
                                  because the reference stack runs in
                                  DetectionOnly. It only becomes a failure here
                                  because a block is all-or-nothing without an
                                  anomaly score to weigh the hit against a
                                  threshold.
  missed-detection  A *positive* test that did not produce a 403 even though the
                    rule is present and in scope. This is the only bucket that
                    represents detection quality. Annotated with an
                    args-splitter suspicion when the upstream rule targets
                    ARGS_NAMES or the request carries several parameters.
  harness           Neither: the response was something other than 403/200/404/
                    405 (only visible with --replay), e.g. Pingora's HTTP parser
                    rejected the request with 400 before the WAF ever saw it.
                    A verdict of "we did not detect this" would be a lie when
                    the request never reached detection, so an out-of-band
                    replay status overrides every other bucket.

`--replay` re-sends every failing test over a raw socket and records the status
code and, for a 403, the rule name lifted out of the block page. That is what
makes the missed-detection list actionable instead of a bare id list.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import socket
import sys
from collections import Counter, defaultdict

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("PyYAML required: pip install pyyaml")


# ── corpus / rule-set loading ────────────────────────────────────────────────

def load_corpus(crs_dir: str) -> dict:
    """Map "<rule>-<test>" to what the CRS test asserts."""
    tests = {}
    root = os.path.join(crs_dir, "tests", "regression", "tests")
    for path in sorted(glob.glob(os.path.join(root, "**", "*.yaml"), recursive=True)):
        with open(path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        if not isinstance(doc, dict) or "tests" not in doc:
            continue
        rule = str(doc.get("rule_id"))
        for case in doc.get("tests") or []:
            stages = case.get("stages") or []
            positive = negative = False
            # The concrete ids each stage asserts on. Cloud mode cannot use
            # these — a status code carries no id — but log mode compares them
            # directly against what go-ftw saw fire.
            expect_ids: set[str] = set()
            no_expect_ids: set[str] = set()
            for stage in stages:
                out = stage.get("output") or {}
                log = out.get("log") or {}
                if log.get("expect_ids") or log.get("match_regex") or out.get("log_contains"):
                    positive = True
                if log.get("no_expect_ids") or log.get("no_match_regex") or out.get("no_log_contains"):
                    negative = True
                expect_ids.update(str(i) for i in (log.get("expect_ids") or []))
                no_expect_ids.update(str(i) for i in (log.get("no_expect_ids") or []))
            tests[f"{rule}-{case['test_id']}"] = {
                "rule": rule,
                "test": case["test_id"],
                "desc": (case.get("desc") or "").strip(),
                "positive": positive,
                "negative": negative,
                "expect_ids": expect_ids,
                "no_expect_ids": no_expect_ids,
                "group": os.path.relpath(path, root).split(os.sep)[0],
                "stages": stages,
            }
    return tests


def load_rules(rules_dir: str) -> dict:
    """Map bare CRS id ("942100") to the converted rule in rules/owasp-crs/."""
    rules = {}
    for path in sorted(glob.glob(os.path.join(rules_dir, "*.yaml"))):
        with open(path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        for rule in (doc or {}).get("rules") or []:
            rid = str(rule.get("id", ""))
            m = re.fullmatch(r"CRS-(\d+)", rid)
            key = m.group(1) if m else rid
            rules[key] = {
                "paranoia": rule.get("paranoia"),
                "name": rule.get("name", ""),
                "field": str(rule.get("field", "")),
                "file": os.path.basename(path),
            }
    return rules


def load_upstream(crs_dir: str) -> dict:
    """Map bare CRS id to the upstream SecRule's file, VARIABLES and phase."""
    upstream = {}
    for path in sorted(glob.glob(os.path.join(crs_dir, "rules", "*.conf"))):
        name = os.path.basename(path)
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        block: list[str] = []

        def flush(block: list[str]) -> None:
            if not block:
                return
            body = "\n".join(block)
            m = re.search(r"\bid:(\d+)", body)
            if not m:
                return
            head = block[0]
            variables = ""
            if head.startswith("SecRule "):
                variables = head[len("SecRule "):].split(" ", 1)[0]
            phase = re.search(r"phase:(\d)", body)
            upstream[m.group(1)] = {
                "file": name,
                "vars": variables,
                "phase": phase.group(1) if phase else "?",
            }

        for line in text.splitlines():
            if line.startswith("SecRule ") or line.startswith("SecAction"):
                flush(block)
                block = [line]
            elif block:
                block.append(line)
        flush(block)
    return upstream


def missing_reason(rid: str, upstream: dict) -> str:
    """Why a tested upstream rule has no counterpart in rules/owasp-crs/."""
    info = upstream.get(rid)
    if not info:
        return "no-upstream-secrule (test targets a rule that is not a plain SecRule)"
    variables, phase, fname = info["vars"], info["phase"], info["file"]
    if fname.startswith("RESPONSE") or phase in ("3", "4"):
        return "response phase — the engine has no response-body inspection channel"
    if "FILES" in variables:
        return "FILES / upload metadata target is not modelled"
    if "MULTIPART_PART_HEADERS" in variables:
        return "MULTIPART_PART_HEADERS target is not modelled"
    if variables.startswith("&"):
        return "header/variable *count* target (&VAR) is not modelled"
    if variables.startswith("TX:") or "TX:/" in variables:
        return "TX sentinel — depends on the anomaly-score / setvar state machine"
    return f"not converted (upstream VARIABLES: {variables or 'n/a'})"


# ── replay ───────────────────────────────────────────────────────────────────

RULE_NAME_RE = re.compile(r"<strong>Reason:</strong>\s*(.*?)<br>", re.S)


def replay(stage: dict, host: str, port: int, timeout: float = 5.0) -> dict:
    """Re-send one stage over a raw socket; return status and blocking rule."""
    inp = stage.get("input") or {}
    if inp.get("encoded_request"):
        return {"status": None, "note": "encoded_request — not replayed"}
    method = inp.get("method", "GET")
    uri = inp.get("uri", "/")
    version = inp.get("version", "HTTP/1.1")
    headers = dict(inp.get("headers") or {})
    data = inp.get("data")
    if isinstance(data, list):
        data = "".join(data)
    body = (data or "").encode("utf-8", "surrogateescape")
    if body and not any(k.lower() == "content-length" for k in headers):
        headers["Content-Length"] = str(len(body))
    if body and not any(k.lower() == "content-type" for k in headers):
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    headers.setdefault("Connection", "close")
    raw = f"{method} {uri} {version}\r\n".encode()
    for key, value in headers.items():
        raw += f"{key}: {value}\r\n".encode("utf-8", "surrogateescape")
    raw += b"\r\n" + body
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(raw)
            chunks = []
            while True:
                buf = sock.recv(65536)
                if not buf:
                    break
                chunks.append(buf)
                if sum(map(len, chunks)) > 262144:
                    break
    except Exception as exc:  # noqa: BLE001 — any transport failure is a datum
        return {"status": None, "note": f"transport: {type(exc).__name__}"}
    payload = b"".join(chunks).decode("utf-8", "replace")
    m = re.match(r"HTTP/[\d.]+ (\d{3})", payload)
    status = int(m.group(1)) if m else None
    rule = None
    hit = RULE_NAME_RE.search(payload)
    if hit:
        rule = re.sub(r"\s+", " ", hit.group(1)).strip()
    return {"status": status, "rule_name": rule}


# ── main ─────────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True, help="go-ftw -o json output")
    ap.add_argument("--extra-results", default=None,
                    help="second go-ftw json (the individually re-run `retry_once` tests) "
                         "merged into the headline number")
    ap.add_argument("--crs", required=True, help="coreruleset checkout")
    ap.add_argument("--rules", required=True, help="rules/owasp-crs directory under test")
    ap.add_argument("--exclusions", default=None)
    ap.add_argument("--waf-log", default=None)
    ap.add_argument("--paranoia", type=int, required=True)
    ap.add_argument("--mode", choices=("cloud", "log"), default="cloud",
                    help="how go-ftw reached its verdicts; changes what the buckets mean")
    ap.add_argument("--crs-version", default="?")
    ap.add_argument("--json-out", default=None)
    ap.add_argument("--apply-exclusions", action="store_true")
    ap.add_argument("--replay", default=None, metavar="HOST:PORT",
                    help="re-send failing tests to this endpoint to record status/rule")
    ap.add_argument("--replay-cache", default=None,
                    help="persist replay results here so the report can be rebuilt "
                         "without a live WAF")
    ap.add_argument("--baseline", default=None,
                    help="baseline json; exit 1 when failures regress beyond it")
    args = ap.parse_args()

    with open(args.results, encoding="utf-8") as fh:
        stats = json.load(fh)
    corpus = load_corpus(args.crs)
    rules = load_rules(args.rules)
    upstream = load_upstream(args.crs)

    # The block page names the rule, not its id, so this is how a replayed 403
    # is traced back to a CRS number.
    name_to_ids: dict[str, set[str]] = defaultdict(set)
    for rid_, rule_ in rules.items():
        name_to_ids[rule_["name"].strip()].add(rid_)

    excl = {"tests": [], "note": ""}
    if args.exclusions and os.path.exists(args.exclusions):
        with open(args.exclusions, encoding="utf-8") as fh:
            excl = yaml.safe_load(fh) or excl

    excluded_ids: dict[str, str] = {}
    for entry in excl.get("exclusions") or []:
        reason = f"{entry.get('gap', '?')}: {entry.get('reason', '')}"
        pattern = re.compile(entry["match"])
        for tid in corpus:
            if pattern.fullmatch(tid):
                excluded_ids[tid] = reason

    passed = set(stats.get("success") or [])
    failed = set(stats.get("failed") or [])
    skipped = set(stats.get("skipped") or [])
    ignored = set(stats.get("ignored") or [])
    # `forced-fail` is the quarantine run.sh applies to the `retry_once` tests so
    # that one of them cannot abort the whole run (go-ftw runner/run.go,
    # `RunTest`). They are failures in the bulk number and are then replaced by
    # their real verdict from --extra-results below, so nothing is double-counted
    # and nothing is dropped from the denominator.
    forced_fail = set(stats.get("forced-fail") or [])
    failed |= forced_fail

    # go-ftw records the rule ids it found in the log for every stage it ran
    # (runner/stats.go, `TriggeredRules map[string][][]uint`). It is empty in
    # cloud mode — `FTWCheck.GetTriggeredRules` returns nil there — and exact in
    # log mode, which is what makes log-mode attribution need no replay.
    triggered_raw = dict(stats.get("triggered-rules") or {})

    if args.extra_results and os.path.exists(args.extra_results):
        with open(args.extra_results, encoding="utf-8") as fh:
            extra = json.load(fh)
        extra_pass = set(extra.get("success") or [])
        extra_fail = set(extra.get("failed") or [])
        # The individual re-run is the authority for these ids.
        passed -= extra_fail
        failed -= extra_pass
        skipped -= extra_pass | extra_fail
        passed |= extra_pass
        failed |= extra_fail
        triggered_raw.update(extra.get("triggered-rules") or {})

    def fired(tid: str) -> set[str]:
        return {str(i) for stage in (triggered_raw.get(tid) or []) for i in (stage or [])}

    host = port = None
    if args.replay:
        host, port_s = args.replay.rsplit(":", 1)
        port = int(port_s)

    replay_cache: dict[str, dict] = {}
    if args.replay_cache and os.path.exists(args.replay_cache):
        with open(args.replay_cache, encoding="utf-8") as fh:
            replay_cache = json.load(fh)

    buckets: dict[str, list] = defaultdict(list)
    for tid in sorted(failed, key=lambda s: (int(s.split("-")[0]), int(s.split("-")[1]))):
        meta = corpus.get(tid)
        if meta is None:
            buckets["harness"].append({"id": tid, "why": "test id not found in corpus"})
            continue
        rid = meta["rule"]
        rule = rules.get(rid)
        entry = {
            "id": tid,
            "rule": rid,
            "group": meta["group"],
            "desc": meta["desc"],
            "polarity": "negative" if meta["negative"] and not meta["positive"] else
                        ("positive" if meta["positive"] else "status-only"),
        }
        if meta["stages"] and (args.replay or tid in replay_cache):
            entry["replay"] = replay_cache.get(tid) or replay(meta["stages"][0], host, port)
            replay_cache[tid] = entry["replay"]

        # An out-of-band status means the request never reached detection —
        # Pingora's HTTP parser answered first. Classifying that as a missed
        # detection would blame the rule set for a framing decision.
        observed = (entry.get("replay") or {}).get("status")
        if observed is not None and observed not in (200, 403, 404, 405):
            entry["why"] = f"request answered {observed} before detection (HTTP parser / gateway)"
            buckets["harness"].append(entry)
            continue

        up = upstream.get(rid, {})
        response_phase = up.get("file", "").startswith("RESPONSE") or up.get("phase") in ("3", "4")

        if rule is None:
            entry["why"] = missing_reason(rid, upstream)
            buckets["not-implemented"].append(entry)
        elif response_phase:
            # The converter emitted these, but the gateway has no response-body
            # inspection channel, so they are dead weight in the rule set. A
            # "missed detection" verdict would suggest a pattern problem when
            # the rule is simply never given anything to look at.
            entry["why"] = ("rule exists in rules/owasp-crs/ but is response-phase — "
                            "the engine never feeds it a response body")
            buckets["not-implemented"].append(entry)
        elif meta["positive"] and (rule["paranoia"] or 1) > args.paranoia:
            entry["why"] = f"rule declares paranoia {rule['paranoia']} > PL{args.paranoia}"
            buckets["paranoia-scope"].append(entry)
        elif meta["negative"] and not meta["positive"]:
            if args.mode == "log":
                # Exact: the ids the test forbids, intersected with the ids
                # go-ftw actually saw in the log. There is no `collateral` half
                # here — a rule the test never named cannot fail it.
                hits = fired(tid)
                offenders = sorted(hits & meta["no_expect_ids"])
                entry["fired_ids"] = offenders
                if rid in offenders:
                    entry["fired"] = rid
                    entry["why"] = "the rule under test fired on a payload CRS says it must not match"
                elif offenders:
                    entry["fired"] = offenders[0]
                    entry["why"] = (f"a rule this test also forbids (CRS-{offenders[0]}) fired")
                else:
                    entry["fired"] = None
                    entry["why"] = ("negative assertion failed with no forbidden id logged "
                                    "(no_match_regex or a status expectation)")
            else:
                hit_name = (entry.get("replay") or {}).get("rule_name")
                fired_ids = name_to_ids.get((hit_name or "").strip(), set())
                if hit_name is None:
                    entry["fired"] = None
                    entry["why"] = "blocked a request CRS expects to pass (firing rule unknown; use REPLAY=1)"
                elif rid in fired_ids:
                    entry["fired"] = rid
                    entry["why"] = "the rule under test fired on a payload CRS says it must not match"
                else:
                    entry["fired"] = sorted(fired_ids)[0] if fired_ids else "?"
                    entry["why"] = (f"a different rule (CRS-{entry['fired']}) blocked; upstream logs it too "
                                    "but scores it instead of blocking outright")
            buckets["over-block"].append(entry)
        elif meta["positive"]:
            suspect = "ARGS_NAMES" in up.get("vars", "")
            if args.mode == "log":
                missing = sorted(meta["expect_ids"] - fired(tid))
                entry["missing_ids"] = missing
                entry["why"] = ("rule present and in scope but its id was never logged"
                                + (f" (missing: {', '.join(missing)})" if missing else
                                   " (match_regex assertion)"))
            else:
                entry["why"] = "rule present and in scope but the payload did not match"
            entry["args_splitter_suspect"] = bool(suspect)
            buckets["missed-detection"].append(entry)
        else:
            entry["why"] = "status-only expectation not met"
            buckets["harness"].append(entry)

    if args.replay_cache and replay_cache:
        with open(args.replay_cache, "w", encoding="utf-8") as fh:
            json.dump(replay_cache, fh)

    total = len(passed) + len(failed) + len(skipped) + len(ignored)
    run = stats.get("run", total)

    def pct(num: int, den: int) -> str:
        return f"{100.0 * num / den:.2f}%" if den else "n/a"

    print("=" * 78)
    print(f"OWASP CRS {args.crs_version} regression suite — prx-waf, PARANOIA LEVEL {args.paranoia}")
    if args.mode == "log":
        print("go-ftw LOG mode (verdict from the rule ids in prx-waf's audit log; "
              "WAF in DetectionOnly)")
        print("  — the posture ModSecurity v2 + CRS and Coraza are measured in")
    else:
        print("go-ftw CLOUD mode (verdict from HTTP status only: block=403, pass=200/404/405)")
        print("  — a negative test here asserts 'nothing blocked', which is stricter "
              "than the corpus means")
    print("=" * 78)
    print(f"  total tests run   {run}")
    print(f"  passed            {len(passed)}   ({pct(len(passed), run)})")
    print(f"  failed            {len(failed)}   ({pct(len(failed), run)})")
    print(f"  skipped           {len(skipped)}")
    print(f"  ignored           {len(ignored)}")
    print()
    print("failures by cause")
    print("-" * 78)
    order = ["not-implemented", "paranoia-scope", "over-block", "missed-detection", "harness"]
    for name in order:
        rows = buckets.get(name) or []
        print(f"  {name:<18} {len(rows):>5}   ({pct(len(rows), len(failed))} of failures)")
    print()

    if buckets["not-implemented"]:
        print("not-implemented — sub-reasons")
        print("-" * 78)
        for reason, count in Counter(r["why"] for r in buckets["not-implemented"]).most_common():
            print(f"  {count:>5}  {reason}")
        print()

    if buckets["paranoia-scope"]:
        print("paranoia-scope — rules above PL%d" % args.paranoia)
        print("-" * 78)
        for reason, count in Counter(r["why"] for r in buckets["paranoia-scope"]).most_common():
            print(f"  {count:>5}  {reason}")
        print()

    if buckets["over-block"]:
        same = [r for r in buckets["over-block"] if r.get("fired") == r["rule"]]
        other = [r for r in buckets["over-block"] if r.get("fired") not in (None, r["rule"])]
        unknown = [r for r in buckets["over-block"] if r.get("fired") is None]
        if args.mode == "log":
            print("over-block — which forbidden rule fired")
            print("-" * 78)
            print(f"  {len(same):>5}  same-rule   the rule under test fired (genuine false positive)")
            print(f"  {len(other):>5}  other-forbidden  another id the same test forbids fired")
            if unknown:
                print(f"  {len(unknown):>5}  no-id       regex/status assertion, not an id assertion")
            print("  collateral is structurally impossible in log mode: a rule the test does")
            print("  not name cannot fail it.")
        else:
            print("over-block — who actually blocked")
            print("-" * 78)
            print(f"  {len(same):>5}  same-rule   the rule under test fired (genuine false positive)")
            print(f"  {len(other):>5}  collateral  another CRS rule fired (upstream scores it, we block on it)")
            if unknown:
                print(f"  {len(unknown):>5}  unknown     no replay data — run with REPLAY=1")
        print()

    for name in ("over-block", "missed-detection"):
        rows = buckets.get(name) or []
        if not rows:
            continue
        print(f"{name} — by rule (top 40 of {len({r['rule'] for r in rows})} rules)")
        print("-" * 78)
        by_rule = Counter(r["rule"] for r in rows)
        for rid, count in by_rule.most_common(40):
            rule = rules.get(rid) or {}
            extra = ""
            if name == "over-block":
                samples = [r for r in rows if r["rule"] == rid][:1]
                hit = (samples[0].get("replay") or {}).get("rule_name") if samples else None
                if hit:
                    extra = f"  ← fired: {hit}"
            print(f"  {count:>5}  CRS-{rid}  {rule.get('name', '(absent)')[:52]}{extra}")
        print()

    if buckets["harness"]:
        print("harness — status the request actually got")
        print("-" * 78)
        for status, count in Counter(
            (r.get("replay") or {}).get("status") for r in buckets["harness"]
        ).most_common():
            print(f"  {count:>5}  HTTP {status}")
        print()

    suspects = sum(1 for r in buckets["missed-detection"] if r.get("args_splitter_suspect"))
    if buckets["missed-detection"]:
        print(f"of the {len(buckets['missed-detection'])} missed detections, {suspects} target a rule "
              f"whose upstream VARIABLES include ARGS_NAMES\n(heuristic: those cannot match without a "
              "per-parameter splitter)")
        print()

    if excluded_ids:
        print("exclusion list (%s)" % ("APPLIED" if args.apply_exclusions else "declared, NOT applied"))
        print("-" * 78)
        for reason, count in Counter(excluded_ids.values()).most_common():
            print(f"  {count:>5}  {reason}")
        hit_fail = len(failed & set(excluded_ids))
        print(f"  {hit_fail} of the {len(excluded_ids)} excluded tests are in the failed set")
        if args.apply_exclusions:
            scoped_run = run - len(excluded_ids)
            scoped_fail = len(failed) - hit_fail
            print(f"  scoped result: {scoped_run - scoped_fail}/{scoped_run} "
                  f"({pct(scoped_run - scoped_fail, scoped_run)})")
        print()

    if args.waf_log and os.path.exists(args.waf_log):
        with open(args.waf_log, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        unrouted = len(re.findall(r"No route found for host", text))
        if unrouted:
            print(f"NOTE: prx-waf answered 404 for an unregistered Host {unrouted} time(s). "
                  f"Add the host to tests/ftw/hosts.txt — 404 is a free pass for negative tests.")
            print()

    report = {
        "crs_version": args.crs_version,
        "paranoia": args.paranoia,
        "mode": args.mode,
        "run": run,
        "passed": len(passed),
        "failed": len(failed),
        "skipped": len(skipped),
        "ignored": len(ignored),
        "pass_rate": round(100.0 * len(passed) / run, 2) if run else 0.0,
        "buckets": {k: len(v) for k, v in buckets.items()},
        "failures": {k: v for k, v in buckets.items()},
        "excluded": len(excluded_ids),
    }
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"machine-readable report: {args.json_out}")

    if args.baseline and os.path.exists(args.baseline):
        with open(args.baseline, encoding="utf-8") as fh:
            base = json.load(fh)
        key = f"PL{args.paranoia}"
        # A baseline is only meaningful within one mode — the two modes ask the
        # WAF different questions and their failure counts are not comparable —
        # so the file is keyed by mode first.
        mode_block = (base.get("modes") or {}).get(args.mode) or {}
        expected = (mode_block.get("results") or {}).get(key)
        if expected is None:
            print(f"BASELINE: no entry for {args.mode}/{key} in {args.baseline} — not gating.")
        else:
            allowed = expected["failed"] + base.get("tolerance", 0)
            print(f"BASELINE {args.mode}/{key}: failed={len(failed)} allowed<={allowed} "
                  f"(baseline {expected['failed']} + tolerance {base.get('tolerance', 0)})")
            if len(failed) > allowed:
                print("BASELINE REGRESSION — more tests fail than the recorded baseline allows.")
                return 1
            if len(failed) < expected["failed"]:
                print("Baseline improved. Update tests/ftw/baseline.json in the same PR.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
