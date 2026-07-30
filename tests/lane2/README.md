# Lane 2 semantic-engine FP/FN corpus

Measures what the Lane 2 semantic engine catches, and what it wrongly flags,
against a committed corpus of 170 attacks and 220 benign requests.

```bash
tests/lane2/run.sh                          # shadow mode (the shipped posture)
MODE=enforce tests/lane2/run.sh             # enforce mode (rollout_bps = 10000)
MODE=shadow,enforce tests/lane2/run.sh      # both
```

One command brings up Postgres, a trivial origin and prx-waf; replays the
corpus; prints a report split by attack family, by detector and by rule; and
tears everything down again.

## Why this exists

Lane 2 is 13 detectors across 10 attack families, with two third-party parsers
(`sqlparser` for SQL, `brush-parser` for shell), `html5ever` for WHATWG DOM
semantics, and one parser of its own (a bounded pickle opcode walker).
**It has never blocked anything.** It
ships `enabled = true`, `enforcement_mode = "log_only"`, `rollout_bps = 0`, and
even flipped to `enforce` the canary bucket is empty, so not one request would
change.

The blocker was never capability, it was evidence. `rollout_bps` cannot be moved
off zero by someone who cannot say what it would cost. `tests/ftw/` answered
that question for the CRS check and is the reason that number can be moved
deliberately; this is the same instrument pointed at the other lane.

## Where we stand

Recorded on 2026-07-30 from the corpus in `corpus/`, at the shipped
`configs/default.toml` posture. The same numbers are the CI gate in
`baseline.json`, which is the authority — this table is transcribed from it.

**A detection rate is meaningless without its mode — always quote both.**

### shadow mode — detection quality

The shipped `log_only` posture, verbatim. Verdicts come from the
`semantic_observations` rows the lane persists.

| | attack (170) | benign (220) |
|---|---|---|
| **detected / false positive** | **139 (81.76%)** | **10 (4.55%)** |
| of which would block | — | **2 (0.91%)** |
| clean | — | 207 |
| sub-threshold | 1 | 3 |
| misattributed / wrong-family | 2 / 2 | — |
| blind | 28 | — |

### enforce mode — the blocking decision

`enforcement_mode = "enforce"`, `rollout_bps = 10000`. Verdicts from HTTP status
codes. This is what actually happens to traffic.

| | attack (170) | benign (220) |
|---|---|---|
| **blocked** | **75 (44.12%)** | **2 (0.91%)** |
| passed | 95 | 217 |
| harness | 0 | 1 |

### By family

| family | n | shadow detected | enforce blocked | benign signals | benign blocked |
|---|---|---|---|---|---|
| `sql_injection` | 20 | 15 (75.0%) | 7 (35.0%) | 2 | 0 |
| `rce` | 20 | 16 (80.0%) | 2 (10.0%) | 6 | 0 |
| `traversal` | 20 | 19 (95.0%) | 2 (10.0%) | 2 | 0 |
| `xss` | 20 | 18 (90.0%) | 3 (15.0%) | 4 | 0 |
| `xxe` | 15 | 13 (86.7%) | 12 (80.0%) | 0 | 0 |
| `nosql_injection` | 15 | 13 (86.7%) | 6 (40.0%) | 0 | 0 |
| `ssti` | 15 | 5 (33.3%) | 5 (33.3%) | 0 | 0 |
| `ldap_injection` | 15 | 12 (80.0%) | 12 (80.0%) | 1 | **1** |
| `xpath_injection` | 15 | 13 (86.7%) | 13 (86.7%) | 1 | **1** |
| `deserialization` | 15 | 15 (100%) | 13 (86.7%) | 0 | 0 |

Detection is flat across difficulty — canonical 84.1%, evasive 83.3%, hard
73.5% — which is not the shape a keyword matcher produces and is the clearest
single piece of evidence that the AST layers are doing real work. The corpus was
written blind (see [Independence](#independence)), so the evasive and hard tiers
were not tuned to what the engine happens to catch.

## The three things this measurement says

**1. Detected and blocked are two very different numbers.** 81.76% versus
44.12%. Most of the gap is the two-detector families: `block_threshold = 80`
with two 0.5 weights needs *both* detectors to agree on the same field, and the
A2 blind guard holds back a Block carried only by a decoded view. So SQLi drops
75% → 35%, RCE 80% → 10%, traversal 95% → 10%, XSS 90% → 15%.

The rest of the gap is confidence. A single-detector family runs at weight 1.0,
so its request score *is* the winning rule's confidence, and it blocks at its
shadow rate only while every rule that fires is over 80. Since v0.2.187 that is
no longer true of three of them: NoSQL 86.7% → 40.0%, deserialization 100% →
86.7%, XXE 86.7% → 80.0%, because the rules turned on in that release carry 45
to 75. Those rows are detections that are deliberately not blocks.

**2. The two families most ready to enforce are the only two that produce
blocking false positives.** `ldap_injection` (80.0% / 1 FP) and
`xpath_injection` (86.7% / 1 FP) are single-detector families whose default-on
rules fire at confidence 88 — over the 80 block threshold on their own. The two
benign requests they block are the same shape:

* `content-099` — an LDAP directory admin page saving
  `(&(objectClass=person)(uid=jsmith))`. Rule: `ldap.filter_break_known_attr`.
* `content-100` — a document-transform tool saving an XPath expression. Rule:
  `xpath.func_axis`.

Both are tools whose *declared input language is the attack grammar*. No
detector improvement fixes that; it is a deployment-scope question (which routes
accept filter syntax), and `enforcement_overrides` is where the answer goes.

**3. The low families were a configuration choice, and one of the two is fixed.**
`nosql_injection` and `ssti` used to sit at 40.0% and 33.3% and look like the
weakest detectors in the set. They were not: both held their high-noise rules
**default-off** pending a calibration nobody could run, so a `$ne` auth bypass
and a `{{7*7}}` probe were out of scope by configuration rather than missed.

`price-rules.sh` runs the whole corpus in both modes with one default-off rule
switched on and nothing else changed, and
[`docs/lane2-rule-pricing.md`](../../docs/lane2-rule-pricing.md) is the resulting
bill for all 38. It says the trade is not one trade. The four NoSQL operator
rules touch **zero** of the 220 benign rows, so v0.2.187 ships them on and that
row is now 86.7%. The bare SSTI delimiters flag benign content at the *same
score* as the attack they catch — `{{7*7}}` and a security article explaining
`{{7*7}}` both score 45 — so no threshold separates them, they stay off, and
33.3% is what SSTI costs to keep the FP column at 10. And
`xpath.bare_double_slash` fires on 94 of the 220 benign rows while catching
nothing at all.

Read `ssti` 33.3% as a price that has been paid deliberately, not as "the SSTI
detector is bad".

The same script pointed the other way (`DIRECTION=disable`) prices a rule that
is already running, by taking it away — that sweep is
[`docs/lane2-rule-pricing.md`](../../docs/lane2-rule-pricing.md#the-eighteen-rules-that-decide-in-code)
for the eighteen rules that decide in code and
[`docs/lane2-latent-pressure.md`](../../docs/lane2-latent-pressure.md) for the
sixty-six that were switchable before them. Between the three sweeps every one
of the 115 keys `prx-waf rules semantic` lists has a number, except
`ast.comment_obfusc`, which is a label rather than a rule and has no switch.

The single most useful number they produce for this table: `xss.script_tag`
carries eight of the eighteen XSS detections **and** two of the ten false
positives, at an identical score of 45 on both, so 90.0% and 4.55% are the same
decision read from two ends.

## What is measured

**Lane 2 and nothing else.** The generated host turns off every Lane 1 detector
(`sqli` / `xss` / `rce` / `dir_traversal` / `bot` / `scan` / `sensitive`) and the
OWASP CRS check. That is not only for attribution: **Lane 1 runs first and
short-circuits on a hit** (`content_security/mod.rs`, `evaluate_scoped`), so with
Lane 1 on, most of the attack corpus would never reach Lane 2 and the number
would be Lane 1's. This mirrors `tests/ftw/`, which turns both lanes off so a CRS
number is a CRS number.

Rate limiting is off too: 390 requests, and the CC auto-ban would poison the
second half of the run.

The `[content_security]` block itself is **sliced out of `configs/default.toml`**
rather than restated in the harness, so a run always measures the posture that
actually ships. Each enforce-mode override is a single-line substitution that
must match exactly once; `run.sh` dies if `default.toml` stops carrying the line
being replaced, so config drift cannot silently change what is measured.

### The two enforce-mode overrides, and why they are not cheating

Enforce mode needs two departures from the shipped config, both recorded in the
report:

* `breaker.window_secs` 300 → 1. The restart shadow latch holds enforcement at
  `Log` until one breaker window has elapsed since process start
  (`mod.rs`, `enforcement_warmed_up`). At the shipped 300 s the harness would
  measure five minutes of nothing.
* `breaker.min_samples` 200 → 1000000. The anomaly-rate breaker counts a Block as
  an anomaly sample, and an attack corpus is ~100% anomalies by construction, so
  at the shipped 200 the breaker would trip part-way through and the second half
  of the corpus would be measured with enforcement already suppressed.

Neither touches detection, scoring or thresholds. They exist because the shipped
values are tuned for production traffic shape and a corpus replay is not that.

## How a corpus row is joined to its verdict

Each row is sent from a **unique loopback source address**
(`127.(16 + n>>16).(n>>8 & 255).(n & 255)`), and that address is the join key.

`semantic_observations` is deliberately de-identified (plan v2.2 §13.1): it
carries the signal breakdown — detector, attack, field, scope, confidence,
`rule_key`, provenance — and nothing that could reconstruct the payload, so it
stores no path and no query. `client_ip` is the only per-request value that
survives into it. `trust_proxy_headers = false` in the generated config means the
WAF takes the peer address verbatim, so the several benign rows that carry their
own `X-Forwarded-For` (on purpose — a private XFF from an internal load balancer
is this product's normal deployment and has been wrongly blocked before) cannot
move their own key.

Matching by insertion order instead does not work: a request that produces no
signal writes no observation, so the two sequences drift apart at the first clean
request and every later attribution is wrong.

The winning family comes from the shadow `security_events` row
(`rule_id` = the winning signal's `rule_key`), mapped back to a family through
the `rule_key → attack` map the observations themselves carry — so the mapping
cannot drift from what the engine emitted.

## The corpus

`corpus/*.jsonl`, one JSON object per line.

| file | rows | what |
|---|---|---|
| `attack-core.jsonl` | 80 | `sql_injection` / `rce` / `traversal` / `xss`, 20 each |
| `attack-t2.jsonl` | 90 | `xxe` / `nosql_injection` / `ssti` / `ldap_injection` / `xpath_injection` / `deserialization`, 15 each |
| `benign-app.jsonl` | 110 | ordinary application traffic: browser page views, REST JSON, search, forms, GraphQL, auth, infrastructure-shaped requests, static assets, i18n |
| `benign-content.jsonl` | 110 | content-shaped false-positive traps: rich text and CMS, templates in content, shell in documentation, SQL in content, crash reports and logs, file uploads, XML, developer tooling |

```json
{"id":"sqli-001","label":"attack","family":"sql_injection","difficulty":"canonical",
 "method":"GET","path":"/search","query":"q=1%27+OR+%271%27%3D%271","headers":{},
 "content_type":null,"body":null,"note":"classic tautology in the query string"}
```

`path` and `query` are written **exactly as they go on the wire**; `send.py`
refuses a row containing a raw space or control character rather than letting
the send fail into the `harness` bucket, where it would read as a WAF anomaly
instead of a corpus bug. Benign rows carry a `trap` tag naming the hazard they
encode (`shell-in-docs`, `private-xff`, `analytics-cookie`,
`template-syntax-in-cms`, `java-stacktrace`, `dollar-key-json`, …).

### Independence

The corpus was written **without reading `crates/`, `rules/` or `fuzz/`**. This
is load-bearing. A corpus derived from the detector source measures whether the
rules match the rules; the detection rate would approach 100% and mean nothing.
The attack rows are canonical public vectors of the PayloadsAllTheThings / OWASP
testing-guide kind, deliberately including a `hard` tier expected to be missed —
a corpus tuned so everything passes is a lie.

### The benign half is the harder half, and the more important one

This repository has been burned by false positives repeatedly, and every one of
those shapes is now a committed row: the `advanced/` rule set that took benign
blocks from 3/40 to 10/40, CRS blocking a request whose only unusual feature was
a private `X-Forwarded-For`, a request carrying only a `_ga` cookie, an ordinary
PDF upload, a CMS saving a Jinja template, a crash report containing a Java stack
trace, a rich-text field holding an XHTML doctype. Those were measured once, in
an ad-hoc `curl` run, and the corpus was thrown away — which is why the numbers
in `rules/README.md` cannot be reproduced today. This one is committed.

`benign-content.jsonl` is aimed squarely at the two AST detectors, because that
is where a semantic engine's false positives actually come from. A README with
`curl -fsSL … | sh`, a Kubernetes manifest whose `args` are a shell pipeline, a
CI config running `bash -c`, a `docker run -v /etc/passwd:/tmp/x:ro` example —
`brush-parser` parses each of these into exactly the syntax tree an attack has,
because they *are* shell commands. They are just shell commands in a
documentation field. Six of the ten false positives come from this group, and
`rce_ast.cmd_subst` alone accounts for five.

### Known corpus limitation: no binary bodies

A row's `body` is a JSON string, so it is UTF-8 on the wire: a `\x89` intended
as one byte becomes two. Five upload rows (`content-066`, `-067`, `-069`,
`-075`, `-078`) therefore carry ASCII stand-ins for PNG/JPEG/XLSX/ZIP payloads
and say so in their `note`. None of them currently produces a signal, so the FP
number is unaffected — but a future magic-byte or content-type-mismatch check
would fire on them as an artefact of the corpus format, not as a real false
positive. Adding a `body_b64` field is the fix when that day comes.
`content-065`'s PDF is genuine ASCII and structurally valid, so the
`pdf-upload` trap is a clean measurement.

## Reading the report

Attack buckets, applied in order:

| bucket | meaning |
|---|---|
| `detected` | the expected family produced a signal, the request crossed a threshold, and the family that won the roll-up is the expected one |
| `misattributed` | crossed a threshold with an expected-family signal present, but another family won the roll-up. Detected; the security event names the wrong attack |
| `sub-threshold` | the expected family fired but the request scored below its `log_threshold`, so no security event was written. **Counted as a miss** — an operator watching the event log did not see it — but it is the cheapest bucket to fix, because it is a threshold and not a blind spot |
| `wrong-family` | no expected-family signal, but another family fired |
| `blind` | no signal at all. The real detection gap |
| `harness` | the request never reached a verdict |

Benign buckets:

| bucket | meaning |
|---|---|
| `clean` | no signal at all |
| `sub-threshold` | signals fired but scored below every threshold. Not an operational FP today, and one threshold change away from being one, which is why it is reported separately and not folded into `clean` |
| `fp-log` | a shadow security event was written for benign traffic |
| `fp-block` | the recommendation was `Block`. **This is the number that gates `rollout_bps`** |

The report also names every false positive and every miss individually, with the
rule keys that fired, and prints per-detector and per-rule tables — so a
regression is diagnosable from the artifact without a re-run.

### Surfaces Lane 2 does not inspect

Lane 2's header scope is a curated list (`SEMANTIC_HEADERS` in `preprocess.rs`:
`user-agent`, `referer`, `x-forwarded-for`, `x-real-ip`, `x-original-url`,
`x-forwarded-host`, `forwarded`, plus `cookie` collected separately). An attack
delivered in, say, `X-Api-Key` is never presented to a detector at all, and
counting it as a missed detection would blame the detectors for a surface
decision. `classify.py` reads that list **out of the engine source** rather than
transcribing it (a transcription rots the first time the list changes) and
prints the affected rows as an advisory, without reclassifying them — one row
today, `ssti-011`, which puts a SpEL expression in `x-api-version`.

## CI

`.github/workflows/lane2-corpus.yml` runs **both modes** on every PR touching
the semantic engine, its config, this directory or `Cargo.lock`. It gates on
`baseline.json`: a job goes red when fewer attacks are detected or more benign
requests are flagged than recorded, or when the corpus shrinks.

**Why this gates and `tests/perf/` does not.** `tests/perf/` deliberately has no
gate, because a latency number on a shared runner is noise and a noisy gate
becomes a `continue-on-error` ornament. This measurement has no such property:
static corpus, config derived from a committed file, detectors that are pure
functions of their input, and the engine's only two time-dependent components
neutralised by `run.sh`. Same inputs, same verdict, on any machine — two runs on
the same tree produced identical numbers. That is the same argument that makes
`crs-regression` a gate, so the tolerance here is **zero**. If this ever starts
flapping, find what stopped being deterministic rather than adding a tolerance.

Both modes run because neither is a superset of the other. Shadow is the
detection-quality gate and the only mode with per-rule attribution. Enforce is
the only mode that can catch a regression in the *blocking* decision: a scoring
change that starts 403-ing benign traffic leaves every shadow observation
untouched, because in shadow nothing blocks.

## Environment knobs

| var | default | meaning |
|---|---|---|
| `MODE` | `shadow` | `shadow`, `enforce`, or both comma-separated |
| `WORK` | `$TMPDIR/prx-waf-lane2` | scratch: generated configs, logs |
| `OUT` | `$WORK/reports` | reports land here |
| `SRC` | repo root | tree to build, to slice `configs/default.toml` from, and to read Lane 2's header scope from |
| `PRXWAF_BIN` | *(built)* | skip the build and use this binary |
| `BASELINE` | *(unset)* | path to `baseline.json`; makes the run gate |
| `RECORDED_FROM` | `PLACEHOLDER-SHA` | stamped into the JSON report |
| `SKIP_POSTGRES` | `0` | a Postgres is already listening on `PG_PORT` (needs a host `psql`) |
| `KEEP` | `0` | leave the environment up for poking at |
| `WAF_PORT` / `WAF_TLS_PORT` / `API_PORT` / `BACKEND_PORT` / `PG_PORT` | `17311` / `17344` / `17399` / `17388` / `15477` | ports — a deliberately uncommon block, because `tests/ftw/` owns `189xx`/`199xx` and a concurrent harness must not be measured instead |

## Known gateway observation

`app-090`, an `OPTIONS` CORS preflight, returns **502** through the gateway
although the harness origin answers the identical request `200` on its own.
Reproduced in both modes, so it is not a Lane 2 verdict — it is counted in the
`harness` bucket rather than as a pass, because a request that never reached a
verdict must not be recorded as having passed. Worth confirming against a
production-grade origin before calling it a gateway bug.
