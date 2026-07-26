# OWASP CRS regression harness

Runs the **official OWASP Core Rule Set regression corpus** — the same
`coreruleset/tests/regression/tests` that ModSecurity and Coraza are measured
against — directly at prx-waf, and classifies the failures.

```bash
tests/ftw/run.sh                        # log mode, paranoia level 1
MODE=cloud tests/ftw/run.sh             # cloud mode, paranoia level 1
PL=1,2,4 tests/ftw/run.sh               # three levels in one go
MODE=cloud PL=1,2 REPLAY=1 tests/ftw/run.sh   # cloud, with per-failure diagnosis
```

One command brings up Postgres, an `albedo` backend, and prx-waf as a reverse
proxy in front of it; fetches the pinned CRS checkout and the pinned `go-ftw`;
runs the suite; prints a classified report; and tears everything down again.

## Where we stand

CRS v4.25.0, go-ftw v1.3.0, 4674 tests, CRS check only. Recorded from `e535a32`
(the `multipart/form-data` part parser) on 2026-07-26; the same numbers are the
CI gate in `baseline.json`.
**A pass rate is meaningless without its mode and its paranoia level — always
quote all three.**

### log mode — the comparable number

WAF in DetectionOnly, verdicts from the rule ids in prx-waf's audit log. This is
the posture ModSecurity v2 + CRS and Coraza are measured in.

| | PL1 | PL2 | PL4 |
|---|---|---|---|
| passed | 2779 | 3742 | 4222 |
| **pass rate** | **59.46%** | **80.06%** | **90.33%** |
| not-implemented | 211 | 211 | 211 |
| paranoia-scope | 1513 | 494 | 0 |
| over-block | 26 | 32 | 34 |
| missed-detection | 144 | 194 | 206 |
| harness | 1 | 1 | 1 |

### cloud mode — the blocking decision

WAF enforcing, verdicts from HTTP status codes.

| | PL1 | PL2 | PL4 |
|---|---|---|---|
| passed | 3216 | 3753 | 3997 |
| **pass rate** | **68.81%** | **80.30%** | **85.52%** |
| not-implemented | 208 | 195 | 182 |
| paranoia-scope | 973 | 286 | 0 |
| over-block | 95 | 251 | 314 |
| missed-detection | 181 | 188 | 180 |
| harness | 1 | 1 | 1 |

Previous recording, for the delta: log `2744 / 3701 / 4176` and cloud
`3185 / 3750 / 3994` at `3018ac1`, measured the same way on the same host. The
multipart parser is **+35 / +41 / +46** in log mode with **zero** new failures at
any level, and **+31 / +3 / +3** in cloud mode. Cloud gains less at PL2/PL4
because 22 of its wins are cancelled by 22 new `over-block` entries that log mode
does not see — 19 of them are CRS-920121 correctly firing at PL2 on the HTML
entity field names in 920120's *negative* tests (`&auml;` contains a `;`, and the
PL2 sibling has no entity exemption, exactly as upstream), which is the
`collateral` artefact described below, not a false positive.

PL4 is the level CRS runs its own regression suite at
(`BLOCKING_PARANOIA: 4` in coreruleset `tests/docker-compose.yml`), so it is
the only row where `paranoia-scope` is empty and the rule set is being asked
the same question upstream asks it. PL1 is the shipping default.

For reference: ModSecurity v2 + CRS is 100% (it is the reference
implementation), Coraza is 100%, ModSecurity v3 is 96–98%. Those are log-mode
numbers, so **`90.33%` at PL4 is the figure that belongs next to them**; the
cloud column is a different question with a different answer.

### Why the two columns disagree in both directions

At PL1 cloud looks *better* (68.81% vs 59.46%) and at PL4 it looks *worse*
(85.52% vs 90.33%). Neither is noise — a status code is a lossy projection of
the corpus's assertions, and it loses information in both directions. Comparing
the two failure **sets** at PL4 (344 tests fail in both modes):

| | count | what it is |
|---|---|---|
| fails only in cloud | 333 | 280 `over-block`, 41 `missed-detection`, 12 `not-implemented` |
| fails only in log | 108 | 67 `missed-detection`, 41 `not-implemented` |

* **Cloud invents failures.** A negative test asserts "rule 941100 did not
  fire". Cloud can only ask "did anything block?", so any *other* rule blocking
  fails it. Those are the 280. Log mode deletes that entire class: `collateral`
  is structurally impossible when the assertion names an id, because a rule the
  test does not name cannot fail it. All 34 of log mode's PL4 `over-block`
  entries are `same-rule` — real false positives of the rule under test.
* **Cloud hands out free passes.** A positive test asserts "rule 933151 fired".
  Cloud can only ask "did anything block?", so when an unrelated rule blocks the
  request the test passes without the rule under test ever matching. Those are
  the 108 — and they are not marginal: 41 of them are for rules that do not
  exist in `rules/owasp-crs/` at all. The same effect explains PL1, where
  cloud's `paranoia-scope` is 973 against log mode's 1513: 540 tests for rules
  that were never even evaluated at PL1 still "passed" in cloud because
  something else blocked.

## The two modes

`go-ftw` has two ways to decide whether a rule fired.

* **log mode** (`MODE=log`, go-ftw's own *default* mode) greps the WAF's log for
  the rule id, synchronising with the log writer through an `X-CRS-Test` marker
  header. It reads the corpus exactly as written.
* **cloud mode** (`MODE=cloud`) looks only at the HTTP status code. A test that
  asserts a rule fires passes iff the response is `403`; a test that asserts no
  rule fires passes iff the response is `200`, `404` or `405`
  (`go-ftw/check/status.go`, `negativeExpectedStatuses`).

### How log mode works here

prx-waf is not ModSecurity, but nothing in go-ftw's log mode is
ModSecurity-specific — it is three requirements, and all three are met by
prx-waf's own rule-hit audit log (`[audit_log]`, `crates/waf-engine/src/audit_log.rs`):

1. **A file with rule ids in it.** `waflog/read.go` matches
   `\[(?:id |\\?"id\\?":)\\?"(\d+)\\?"\]` (and a JSON variant) against each line,
   so a line carrying `[id "942100"]` is all it needs. The audit log writes one
   such line per matched rule, plus one carrying `[id "949110"]` when the
   anomaly score reaches the threshold — which is exactly what upstream's
   `REQUEST-949-BLOCKING-EVALUATION.conf` logs.
2. **Marker synchronisation.** Before and after every stage go-ftw sends
   `GET /status/200` with `X-CRS-Test: <uuid>-s` / `-e` and then reads the log
   backwards until it finds a line containing that value
   (`runner/run.go`, `markAndFlush`; retried up to 20 times, 500 lines back). It
   then reads only the lines *between* the two markers
   (`waflog/read.go`, `getMarkedLines`, whole-line equality). `audit_log.marker_header`
   makes prx-waf echo that header — and log **nothing else** for that request,
   the way upstream's marker rule ends in `ctl:ruleRemoveById=1-999999`
   (`coreruleset/modsecurity-crs-docker`, `src/opt/modsecurity/configure-rules.sh`),
   so the marker request cannot contaminate the window it delimits.
3. **DetectionOnly.** The corpus was written against
   `MODSEC_RULE_ENGINE: DetectionOnly` (coreruleset `tests/docker-compose.yml`).
   `run.sh` sets `log_only_mode = true` on every generated host. Without it the
   negative tests would fail for being blocked rather than for being logged, and
   a positive test's later rules would never be reached.

The audit log is **off by default** and the harness is the one turning it on;
see `configs/default.toml`.

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
see the `over-block` `same-rule` / `collateral` split, which at PL4 is 68 vs
211. Log mode is the fix, not a workaround: it asks the question the corpus
actually asks.

## What the run measures

The CRS check and nothing else. Every prx-waf-native Lane 1 detector
(`sqli`, `xss`, `rce`, `dir_traversal`, `bot`, `scan`, `sensitive`) is switched
off in the generated config, the Lane 2 semantic engine is left at its default
off, and response caching is off. A pass can therefore only come from a CRS
rule, and a false positive can only be blamed on a CRS rule — which is what
makes the number comparable to ModSecurity+CRS or Coraza+CRS.

Rate limiting (`cc`) is off too: `go-ftw` sends ~4.7k requests from one source
address in cloud mode and ~14k in log mode (two marker requests per stage),
which would otherwise trip the CC auto-ban and poison the run.

## The `retry_once` quarantine

Five corpus tests (`959100-1`, `959100-3`, `980170-1/-2/-3`) carry
`output.retry_once`, added upstream for a phase-5 log race. go-ftw retries such
a test once and then **propagates the error out of the whole run**
(`runner/run.go`, `RunTest` → `Run`): no results file, no summary, exit 1. A WAF
that fails one of them therefore gets no number at all — which is what happened
here the moment anomaly scoring landed and `980170-2` ("a request that scored but
was not blocked") stopped returning 403.

`run.sh` handles this without touching the denominator: the five are
`forcefail`-quarantined out of the bulk run (`forcefail`, not `ignore` or
`forcepass` — they stay counted as failures), then each is re-run on its own with
an unmodified config, and `classify.py` merges those individual verdicts back in
through `--extra-results`. A solo run that aborts is that one test failing. The
list is read out of the corpus, not hard-coded, so a CRS bump that marks another
test `retry_once` cannot silently reintroduce the abort.

**These five are the only part of the score that is not fixed by static inputs,
so record their verdicts whenever you record a baseline.** At the recording in
`baseline.json` they are, in both independent runs and at every level:

| | log mode | cloud mode |
|---|---|---|
| 959100-1, 959100-3 | pass | pass |
| 980170-1 | **fail** | pass |
| 980170-2 | **fail** | **fail** |
| 980170-3 | pass | pass |

They all sit in `not-implemented` when they fail (`RESPONSE-980-CORRELATION.conf`
has no converted counterpart), so a flip here moves that bucket by one without
any rule changing. That is the most likely explanation for the log-mode `+1`
between the `3018ac1` re-measurement and the figure this file carried before it —
see the `_comment` block in `baseline.json`.

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
| `not-implemented` | the rule id is **absent from `rules/owasp-crs/` altogether** — `TX` collection sentinels, `&VAR` counts, `setvar`-driven rules the converter refuses. Note what this does *not* cover: see the trap below |
| `paranoia-scope` | the rule exists but declares a higher paranoia level than the run enabled; upstream skips it too |
| `over-block` | a negative test the WAF got wrong. **log mode**: the id the test forbids appeared in the audit log — always a genuine false positive, since a rule the test does not name cannot fail it. **cloud mode**: the request got a `403`; split by `REPLAY=1` into **same-rule** (the rule under test fired) and **collateral** (another CRS rule fired; upstream scores it instead of blocking) |
| `missed-detection` | a positive test whose rule is present, in scope, and request-phase, but did not match — **the main detection-quality bucket**. In log mode the report names the exact ids that were expected and never logged |
| `harness` | the response was neither a block nor a pass, e.g. Pingora answered `400` before the WAF saw the request |

### The trap: `not-implemented` is not "the engine cannot evaluate this"

`classify.py` decides this bucket with one test — `if rule is None`, i.e. is the
id present in the YAML the run was pointed at (`classify.py`, `--rules`). That is
**not** the same question as "does the engine enforce it", and the difference has
already misled one round of planning:

* A rule the converter emitted with an `unmapped_*` field is **present in the
  YAML** and **rejected at load** with a startup `WARN`. It enforces nothing, but
  `classify.py` sees a rule, so its failures land in **`missed-detection`**.
  Before the multipart parser landed, all five `FILES` rules (932180, 933110,
  933111, 933220, 944140) and both `MULTIPART_PART_HEADERS` rules (922120,
  922130) were in exactly that state — 76 failing tests sitting in
  `missed-detection`, not in `not-implemented`.
* So **sizing a capability gap from the `not-implemented` count under-counts it**.
  The number to size from is the engine's own load summary: the
  `[unsupported-field]` lines in the startup `WARN`, which name every rule that
  is declared but not enforced, and `LoadSummary::rejected_field_ids()` behind
  them.

A response-phase rule that is present in `rules/owasp-crs/` is *not* special
either, not any more: the gateway feeds it a response body like any other rule,
so its failures are ordinary missed detections, over-blocks or paranoia-scope
exclusions and are counted as such.

`REPLAY=1` re-sends every failing test and records the status code, plus the
rule name lifted out of the block page for anything that returned `403`. In
cloud mode that turns `over-block` from a count into a named list of over-eager
rules. In log mode the rule attribution comes from go-ftw itself
(`triggered-rules` in its JSON output — exact, and available without a replay),
so `REPLAY=1` there earns only the `harness` split: it is what distinguishes "we
did not detect this" from "Pingora answered `400` before the WAF saw the
request", which is true in DetectionOnly too.

## Sizing a capability before you build it

Twice now a capability has been sized by counting the regression tests that name
the rules it would turn on, and twice the estimate has come out roughly double.
The correction is cheap and mechanical, so it belongs here.

**A rule's test count is an upper bound, not an estimate.** Before committing to a
number, split the corpus for each rule by *how the test delivers the payload* and
keep only the transports the change actually implements. The
`multipart/form-data` parser is the worked example — it was scoped at "100+ tests"
and delivered **+46** at PL4:

| rule | positive tests | via multipart upload | via `X-Filename`-style **header** | delivered |
|---|---|---|---|---|
| 920120 | 20 | 20 | 0 | **20 / 20** |
| 920121 | 6 | 6 | 0 | **6 / 6** |
| 922120 | 1 | 1 | 0 | **1 / 1** |
| 922130 | 4 | 4 | 0 | **4 / 4** |
| 932180 | 11 | 2 | 9 | **2 / 2** |
| 933110 | 30 | 3 | 27 | **3 / 3** |
| 933111 | 6 | 5 | 1 | **5 / 5** |
| 933220 | 13 | 2 | 11 | **2 / 2** |
| 944140 | 11 | 2 | 9 | **2 / 2** |

Every multipart-delivered positive test converted — 45 of 45, plus one 930110
test that the parser earned by adding `FILES` to that rule's surface list. The
57-test shortfall is not a defect in the parser: those tests send the file name
in `REQUEST_HEADERS:X-Filename` / `X_Filename` / `X.Filename` / `X-File-Name`,
because CRS writes both delivery mechanisms into one `SecRule`. Reaching them
needs a **generic `REQUEST_HEADERS:<name>` accessor** (`Field::parse` currently
knows six headers by name), which is a different capability that happens to share
a rule id.

Two more 922 rules are out of reach for a third reason — they need a variable
store, not a parser:

* **922110** (17 tests) reads `TX:/MULTIPART_HEADERS_CONTENT_TYPES_*/`, a
  collection that upstream rule 922150 fills in with `setvar`, one entry per
  part. The converter models no variable store and refuses the rule as not
  expressible.
* **922100** (2 tests) is `&MULTIPART_PART_HEADERS:_charset_` — a count over the
  headers of one *named* part — chained against `ARGS._charset_` and a `setvar`
  allow-list.

So the three questions to ask of any "N tests" estimate are: *which transport does
each test use*, *is the variable the rule reads actually the one this change
produces*, and *does the rule need `setvar`*. The first alone accounted for the
whole gap here.

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
| `MODE` | `log` | `log` (corpus as written, DetectionOnly, verdicts from the audit log) or `cloud` (verdicts from HTTP status codes, WAF enforcing) |
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

`.github/workflows/crs-regression.yml` runs **both modes at PL1 and PL2** — four
independent jobs — on every PR that touches the rules, the engine, the gateway
or this directory. It gates on `baseline.json`: a job goes red only when *more*
tests fail than the recorded baseline for that mode and level, plus its
tolerance. The baseline is a file, not a workflow constant, so raising or
lowering it is a reviewable diff in the PR that earned it.

Both modes run because neither is a superset of the other. Log mode is the
detection-quality gate and the only number comparable to upstream. Cloud mode is
the only one that can catch a regression in the *blocking* decision: a change to
the scoring model that starts blocking benign traffic leaves every log-mode
assertion untouched, because in DetectionOnly nothing is blocked by definition.
