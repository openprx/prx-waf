# Runtime performance harness

Measures what prx-waf costs at runtime: throughput, latency including the tail,
CPU per request and memory, broken down **per detection layer** so the number
can be attributed rather than just quoted.

```bash
tests/perf/run.sh                                  # every posture, every workload
POSTURES=origin,passthrough,full tests/perf/run.sh # the three that matter most
WORKLOADS=get-small ROUNDS=5 tests/perf/run.sh     # one workload, tighter median
DURATION=30 CONNECTIONS=100 tests/perf/run.sh
WORKER_THREADS=1 tests/perf/run.sh                 # the pre-0.2.63 data plane
LANE1_MAX_BODY_BYTES=0 tests/perf/run.sh           # unbounded Lane 1 bodies
```

One command brings up Postgres, an `albedo` origin and prx-waf, drives load with
`oha`, and writes `raw.jsonl` (one record per posture/workload/round),
`summary.json` and `summary.md`. Nothing is left running.

## The other two scripts here

`run.sh` answers "what does a posture cost per request". Two questions it cannot
answer have their own instruments, deliberately kept separate so a change to one
cannot move the other's numbers:

```bash
tests/perf/soak.sh                              # does memory converge under attack?
RATE=2000 MINUTES=20 tests/perf/soak.sh         # a rate-limited attacker
STALL_DB_AT=20 STALL_DB_FOR=40 tests/perf/soak.sh   # freeze the database mid-run
tests/perf/quiet_check.sh <pid> 0-3 8           # were the subject's cores its own?
```

**[`soak.sh`](soak.sh)** measures the *shape* of the memory curve rather than its
peak. `run.sh` reports the highest RSS it saw in ten seconds, which cannot
distinguish a process that settles at a working set from one that rises until a
queue bound stops it from one that rises for as long as traffic keeps arriving —
the three have identical first ten seconds and completely different operational
meanings. It samples RSS, CPU, per-queue depth, pool occupancy, the drop counters
and the rows that actually reached the database once a second;
[`soak_shape.py`](soak_shape.py) fits the second half of the series and states
the rule it used, so the verdict is arithmetic a reader can check. It stops
itself at `RSS_ABORT_MIB` rather than OOM-ing the host, and an abort is reported
as a result. Results are in [`RESULTS.md`](RESULTS.md) §8.

**[`quiet_check.sh`](quiet_check.sh)** implements the host-quiet criterion this
page switched to when the data plane went multi-threaded: compare the busy
jiffies on the subject's pinned cores against the subject's own `utime+stime`
over the same window and report the residual. It has to run *during* a
measurement — a background process that wakes up halfway through leaves no trace
in a before/after load average.

---

## Why this is not a CI gate

The CRS regression harness next door (`tests/ftw/`) **is** a gate: it has a
`baseline.json` ratchet and a failure there is a real regression. This harness
deliberately has neither, and that is a design decision, not an omission.

A performance number on a shared CI runner has a spread wider than the effect
being measured. The rounds recorded below disagreed with each other by up to
**2× in RPS** on a developer machine that merely had other builds running —
while the CPU-per-request figure for the same rounds held within 5%. A gate
built on the RPS number would fail constantly for reasons unrelated to the
change, and the well-worn resolution to a constantly-failing gate is
`continue-on-error: true`. At that point the repository has a green check mark
that means nothing, which is strictly worse than having no check at all: it
converts "we do not measure this in CI" into "we measure this in CI and it
passes", and only the second one misleads.

So: run this by hand before and after a change that could plausibly affect the
data path, compare, and put the numbers in the pull request where a human reads
them. If a gate is ever wanted, gate on `cpu_us_per_req` — not on RPS or latency
— and only on a dedicated, idle, pinned machine.

---

## What is measured against what

"The WAF costs X" is meaningless without a reference, and one reference is not
enough, because two different costs get confused:

* **the proxy hop** — accept, parse, route, pool an upstream connection, relay
  the response. Any reverse proxy pays this.
* **the detection** — the regex lanes, the CRS rule set, the semantic engine.
  Only a WAF pays this.

So there are two references:

| Posture | What it is |
|---|---|
| `origin` | the generator straight at `albedo`, no proxy in the path |
| `passthrough` | the real shipping prx-waf binary with every detector switched off |

`origin` is **not a competitor — it is a ceiling.** Without it you cannot tell
whether a posture's RPS is the WAF's limit or the test rig's limit, and every
conclusion below it is unfalsifiable. `passthrough` is the proxy hop on its own.

```
origin → passthrough    the cost of putting a reverse proxy in the path
passthrough → posture   the cost of that posture's detection, and nothing else
```

**Deliberately not the reference: nginx, or a hand-written bare Pingora proxy.**

nginx would answer a different question. The delta would fold "Rust Pingora vs
C nginx" into "detection cost", which is exactly the term this harness exists to
isolate. It is a fine *product* comparison and a bad *attribution* baseline; it
belongs in a separate exercise with its own methodology.

A bare Pingora binary would be a second program with its own drift, and it would
exclude whatever the WAF framework costs before it consults a single rule.
Running the shipping binary with detection off measures the code path that
actually runs in production, which is the more honest answer even though it is
the less flattering one.

### Postures

Each adds exactly one layer to `passthrough`, so a subtraction attributes cost
to a layer rather than to a lump sum.

| Posture | Layer added |
|---|---|
| `passthrough` | — (proxy only) |
| `lane1` | native regex detectors: sqli, xss, rce, scan, traversal, sensitive, bot |
| `crs-pl1` | OWASP CRS at paranoia 1 — the shipping default level |
| `crs-pl2` / `crs-pl4` | OWASP CRS at paranoia 2 / 4 — the paranoia cost curve |
| `lane2` | the Lane 2 semantic engine in its shipping shadow posture (`log_only`, `rollout_bps = 0`) |
| `cc` | the per-IP rate limiter, on its own |
| `full` | lane1 + CRS PL1 + lane2 + cc — the shipping default |

The CRS postures are cumulative over `passthrough`, **not** over `lane1`, so the
CRS figure is not contaminated by Lane 1. `full` is the only posture that stacks
everything, and it is the number an operator experiences.

Two details that affect how the deltas should be read:

* **The CRS rule set is parsed and loaded in every posture**, including
  `passthrough` — rule loading follows `[rules] dir`, and only *evaluation* is
  gated by the per-host `owasp_set` toggle. So the `crs-pl1` delta is the cost
  of *evaluating* 285 rules per request, not the cost of having them in memory.
  Baseline RSS already includes them.
* **The rate limiter in the `cc` posture is configured never to fire**
  (`cc_rps = 1e6`, `cc_burst = 2e6`). The cost measured is the token-bucket
  lookup on every request, which is what a healthy deployment pays. A limiter
  that starts returning 429 measures the 429 path, not the limiter.

### Workloads

| Workload | Shape |
|---|---|
| `get-small` | `GET /get?q=…&page=2&sort=…`, no body |
| `json-post` | `POST` 1 KiB `application/json` — a typical API write |
| `form-post` | `POST` 512 B `application/x-www-form-urlencoded` — a login/checkout shape |
| `multipart` | `POST` 64 KiB `multipart/form-data`, two text fields plus a file part |
| `body-1mb` | `POST` 1 MiB JSON — exercises the buffer-then-scan window path |
| `attack` | union-select SQLi in a query parameter |

Payloads are **generated from a fixed recipe at run time, not committed**. A
1 MiB fixture in git is noise; the recipe is what makes the workload
reproducible.

`attack` is reported but is **not comparable to the benign rows**: a blocked
request is answered with 403 and never reaches the origin, so it skips a hop the
others pay for. Read it as "what does the block path cost", not as "what does
the WAF cost under attack".

**Every request carries a browser `User-Agent`, and that is load-bearing.**
Lane 1's bot detector blocks `curl/*` outright — a bare
`curl http://waf/get?hello=world` returns **403** with `bot = true`. Measuring
with a generator whose UA is blocked would compare the block page in the
postures that have the bot detector on against the upstream hop in the ones that
do not, and call the difference "detection cost". (This is also worth knowing
operationally: default-configured prx-waf will 403 your `curl`-based health
checks and deployment scripts.)

### Held constant across every posture

* **Response caching is OFF, including in `full`.** A cache hit skips the
  upstream entirely and would make the WAF measure *faster* than the origin it
  fronts — a real feature, but it would drown every detection delta this
  harness exists to isolate. Measuring the cache is a separate question needing
  a separate workload mix (repeat rate, key cardinality).
* **GeoIP is OFF.** The xdb databases are not shipped, so leaving it enabled
  would measure a lookup that silently no-ops — a zero with a misleading name.
* **The audit log is OFF.**
* Benign traffic produces no detections, so the Postgres write path is off the
  hot path for five of the six workloads. It is very much *on* the hot path for
  `attack`, which is part of why that row is not comparable.

### Two settings the harness will change on request

Everything above is fixed. Two things are not, because their **defaults
changed** after the first matrix was recorded, and a table that cannot say which
side of the change it sits on is comparable to nothing:

| Knob | Default | What the other setting is |
|---|---|---|
| `WORKER_THREADS` | unset — `[proxy] worker_threads` follows the CPUs the process may use | `WORKER_THREADS=1` is the single-threaded data plane every release before 0.2.63 had, whatever the machine |
| `LANE1_MAX_BODY_BYTES` | unset — 64 KiB, the shipped default since 0.2.64 | `LANE1_MAX_BODY_BYTES=0` is unbounded Lane 1, which is what every release before it did |

Under pinning the worker-thread default follows `taskset`, not `nproc`:
`available_parallelism` reads the affinity mask, so the default run is
`WAF_CPUS`-wide. Both settings are written into the generated TOML in `$WORK`
and recorded in `summary.json` under `method`, so a summary always states which
posture produced it.

---

## Metrics, and which one to trust

`oha` was chosen over `wrk`, `ab` and `hey` for one specific reason: its JSON
output carries **p99.9**. A WAF's characteristic failure is tail latency — a
rule that occasionally does something expensive — and a tool that stops at p99
cannot show it. (`wrk` also needs a Lua script for POST bodies and emits no
machine-readable tail; `ab` is single-threaded and HTTP/1.0.)

Reported per cell:

| Metric | Meaning |
|---|---|
| RPS | requests/second |
| p50 / p95 / p99 / p99.9 | latency percentiles, ms |
| **CPU µs/req** | subject-process CPU time ÷ requests served |
| RSS | peak resident set, sampled at 5 Hz |
| RPS spread / µs spread | (best − worst) over the rounds, as a share of the median |

**Read the layer attribution from CPU µs/req, not from RPS.** RPS and latency
measure "how fast was this host at that moment"; on a machine that is not
exclusively yours they move with whatever else is running. CPU per request
measures "how much work does the WAF do for one request", which is a property of
the code. Contention makes each request take longer in wall time without making
it cost more cycles, so this figure survives a noisy host where RPS does not —
which is exactly what the recorded rounds show.

One caveat on that column: **the `origin` row's µs/req is albedo's CPU, not
prx-waf's.** It is a different program in a different language, so µs/req is
only comparable *between prx-waf postures*. Use RPS for the origin comparison
and µs/req for the layer attribution.

The two spread columns exist so a reader can tell a result from noise without
taking anyone's word for it. **Treat any figure whose spread is above ~10% as
noise.**

### Reproducibility

* Everything that can drift is pinned: `oha` version, `albedo` version, the
  Postgres image, the connection count and the duration. **A performance number
  is only comparable to another produced by the same generator at the same
  version against the same origin, at the same connection count.** Restate all
  four whenever a figure is quoted.
* Three rounds per cell; the **median round by RPS** wins, and its latency
  figures are reported from that same round. Taking the median of each column
  independently would synthesise a row no run ever produced.
* CPU pinning is on by default — WAF on cores 0–3, origin on 4–9, generator on
  10–15. Generator, origin and subject share one host, and without disjoint core
  sets they fight for the same cores and the "WAF cost" absorbs scheduler noise.
  `PIN=0` disables it; expect wider spread.
* `summary.json` records `recorded_from.tree` **and**
  `recorded_from.worktree_state`. A number measured on a tree with uncommitted
  changes is not reproducible, and it says so in the data rather than in a
  footnote nobody reads.
* The host's 1-minute load average is recorded at the start and end of the run.
  A shared host still produces a legitimate measurement, but a *different kind*
  of measurement from an idle one, and the reader has to be able to tell which
  one they are holding.

---

## Results

See [`RESULTS.md`](RESULTS.md).
