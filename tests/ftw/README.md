# OWASP CRS regression harness

Runs the **official OWASP Core Rule Set regression corpus** — the same
`coreruleset/tests/regression/tests` that ModSecurity and Coraza are measured
against — directly at prx-waf, and classifies the failures.

```bash
tests/ftw/run.sh                 # paranoia level 1 (factory default)
PL=2 tests/ftw/run.sh            # paranoia level 2
PL=1,2 REPLAY=1 tests/ftw/run.sh # both levels, with per-failure diagnosis
```

One command brings up Postgres, an `albedo` backend, and prx-waf as a reverse
proxy in front of it; fetches the pinned CRS checkout and the pinned `go-ftw`;
runs the suite; prints a classified report; and tears everything down again.

## Where we stand

CRS v4.25.0, go-ftw v1.3.0, cloud mode, 4674 tests, CRS check only. Recorded
from `35fedb5` on 2026-07-25; the same numbers are the CI gate in
`baseline.json`. **A pass rate is meaningless without its paranoia level —
always quote both.**

| | PL1 | PL2 | PL4 |
|---|---|---|---|
| passed | 3133 | 3683 | 3915 |
| **pass rate** | **67.03%** | **78.80%** | **83.76%** |
| not-implemented | 290 | 246 | 248 |
| paranoia-scope | 928 | 283 | 0 |
| over-block | 107 | 237 | 349 |
| missed-detection | 177 | 188 | 125 |
| harness | 39 | 37 | 37 |

PL4 is the level CRS runs its own regression suite at
(`BLOCKING_PARANOIA: 4` in coreruleset `tests/docker-compose.yml`), so it is
the only column where `paranoia-scope` is empty and the rule set is being asked
the same question upstream asks it. PL1 is the shipping default.

For reference: ModSecurity v2 + CRS is 100% (it is the reference
implementation), Coraza is 100%, ModSecurity v3 is 96–98%.

## Why cloud mode

`go-ftw` has two ways to decide whether a rule fired.

* **log mode** greps the WAF's log for the rule id, synchronising with the log
  writer through an `X-CRS-Test` marker header. It is built around
  ModSecurity's audit-log format and its marker/flush semantics.
* **cloud mode** looks only at the HTTP status code. A test that asserts a rule
  fires passes iff the response is `403`; a test that asserts no rule fires
  passes iff the response is `200`, `404` or `405`
  (`go-ftw/check/status.go`, `negativeExpectedStatuses`).

prx-waf is not ModSecurity and has no ModSecurity audit log, so cloud mode is
the only honest option. It also means the harness measures the *decision*, which
is what a user experiences, rather than a log line.

### The trap in cloud mode, and what `gen_overrides.py` does about it

`go-ftw run --cloud` pointed straight at the CRS corpus reports **~100% and
means nothing**. The corpus is written against a stack running
`SecRuleEngine DetectionOnly`, so it asserts on the audit log and carries
almost no `output.status`. `AssertStatus` opens with
`if c.expected.Status == 0 { return true }` and `AssertLogs` returns `true`
unconditionally in cloud mode — so with no status in the test, *nothing is
checked*. We measured this: a naive cloud run scored 4664/4674.

`gen_overrides.py` closes the gap by generating a go-ftw platform-overrides
file (`--overrides`, the mechanism CRS ships `coraza-overrides.yaml` through)
that restates each existing assertion as its blocking-mode equivalent —
`expect_ids` → expect `403`, `no_expect_ids` → expect `200` — copying the
original `log:` block through untouched. Stages that already declare their own
`status`, and stages that assert `expect_error`, are left alone. No test is
dropped and no id is filtered.

One consequence has to be stated plainly, because it inflates the failure
count: in blocking mode a negative test effectively asserts *"no rule at all
fires"*, while the corpus only means *"rule X does not fire"*. When some other
CRS rule blocks the request the test fails even though upstream would have
logged that rule and moved on. The classifier separates exactly this case —
see the `over-block` `same-rule` / `collateral` split, which at PL4 is 75 vs
274.

## What the run measures

The CRS check and nothing else. Every prx-waf-native Lane 1 detector
(`sqli`, `xss`, `rce`, `dir_traversal`, `bot`, `scan`, `sensitive`) is switched
off in the generated config, the Lane 2 semantic engine is left at its default
off, and response caching is off. A pass can therefore only come from a CRS
rule, and a false positive can only be blamed on a CRS rule — which is what
makes the number comparable to ModSecurity+CRS or Coraza+CRS.

Rate limiting (`cc`) is off too: `go-ftw` sends ~4.7k requests from one source
address, which would otherwise trip the CC auto-ban and poison the run.

`hosts.txt` registers every `Host:` value that appears anywhere in the corpus.
prx-waf answers `404` for an unknown Host, and `404` is a *pass* for negative
tests — an unregistered host would silently inflate the score. The classifier
prints a warning if the WAF log shows any unrouted host, so this cannot rot
quietly.

## Reading the report

Failures are split by cause, because only one of the groups is a detection
defect:

| bucket | meaning |
|---|---|
| `not-implemented` | the rule does not exist in `rules/owasp-crs/` — response phase, `FILES`, `MULTIPART_PART_HEADERS`, `&VAR` counts, `TX` sentinels |
| `paranoia-scope` | the rule exists but declares a higher paranoia level than the run enabled; upstream skips it too |
| `over-block` | a negative test that got a `403`. Split by `REPLAY=1` into **same-rule** (the rule under test fired — a genuine false positive) and **collateral** (another CRS rule fired; upstream scores it instead of blocking) |
| `missed-detection` | a positive test whose rule is present, in scope, and request-phase, but did not match — **the main detection-quality bucket** |
| `harness` | the response was neither a block nor a pass, e.g. Pingora answered `400` before the WAF saw the request |

A response-phase rule that *is* present in `rules/owasp-crs/` still counts as
`not-implemented`, not `missed-detection`: the converter emitted it but the
gateway never hands it a response body, so calling it a detection miss would
blame the pattern for a plumbing gap.

`REPLAY=1` re-sends every failing test and records the status code, plus the
rule name lifted out of the block page for anything that returned `403`. That
turns `over-block` from a count into a named list of over-eager rules.

## Exclusions

`exclusions.yaml` is deliberately empty. The headline number is computed over
the **full** corpus; gaps are reported as classified failures rather than
subtracted from the denominator. `APPLY_EXCLUSIONS=1` additionally prints an
exclusion-scoped number, and the exclusion list itself is always printed with a
per-entry reason. Entries may only be added for tests that cannot be *executed*
meaningfully — never for tests that merely fail.

## Pins

| thing | pin | why |
|---|---|---|
| coreruleset | `v4.25.0` | matches the version `rules/owasp-crs/README.md` was converted from |
| go-ftw | `v1.3.0` | verdict semantics (`negativeExpectedStatuses`) are version-dependent |
| albedo | `v0.3.0` | the backend CRS itself uses upstream |
| postgres | `16` | matches `docker-compose.yml` |

## Environment knobs

| var | default | meaning |
|---|---|---|
| `PL` | `1` | comma-separated paranoia levels to run |
| `WORK` | `$TMPDIR/prx-waf-ftw` | scratch: CRS checkout, go tools, generated configs, logs |
| `OUT` | `$WORK/reports` | reports land here |
| `SRC` | repo root | tree to build and to load `rules/owasp-crs/` from |
| `PRXWAF_BIN` | *(built)* | skip the build and use this binary |
| `REPLAY` | `0` | re-send failures to record status + blocking rule |
| `BASELINE` | *(unset)* | path to `baseline.json`; makes the run gate on regressions |
| `APPLY_EXCLUSIONS` | `0` | also print the exclusion-scoped number |
| `SKIP_POSTGRES` | `0` | a Postgres is already listening on `PG_PORT` |
| `KEEP` | `0` | leave the environment up for poking at |
| `WAF_PORT` / `API_PORT` / `BACKEND_PORT` / `PG_PORT` | `18081` / `19527` / `18088` / `15433` | ports |

## CI

`.github/workflows/crs-regression.yml` runs PL1 and PL2 on every PR that
touches the rules, the engine, the gateway or this directory. It gates on
`baseline.json`: the job goes red only when *more* tests fail than the recorded
baseline plus its tolerance. The baseline is a file, not a workflow constant, so
raising or lowering it is a reviewable diff in the PR that earned it.
