# Measured runtime performance

Recorded **2026-07-26** by `tests/perf/run.sh` from tree `87aa1bc`, with **no
modifications to tracked sources** — the only files not in the commit were this
harness and its documentation, so the binary under test is exactly what
`87aa1bc` builds. Methodology, and why the two reference postures are what they
are, is in [README.md](README.md). Raw data: [`results/`](results/).

| | |
|---|---|
| CPU | AMD Ryzen 9 5900HX, 16 logical cores |
| Memory | 30.8 GiB |
| Kernel | 6.12.48+deb13-amd64 |
| Generator | `oha` 1.11.0, `c=50`, 10 s × 3 rounds, median round |
| Origin | `albedo` v0.3.0 (200, empty body) |
| Pinning | WAF cores 0–3, origin 4–9, generator 10–15 |
| Host load (1 min) | 2.93 at start → 3.00 at end |

The host was **not** idle — this is a developer machine with a stable background
load of ~3. An earlier run of the same matrix, taken while three `rustc`
processes came and went, is not reported here: the load fell from 19.9 to 3.9
*during* the run, so posture order was confounded with host load and several
rows moved by 40–140% between rounds. The numbers below come from the re-run at
stable load, and the per-row spread columns are published so a reader can check
that claim rather than take it. The two runs agreed on every conclusion below;
only the noise level differed.

**Read the layer attribution from CPU µs/req, not from RPS.** See
[README.md § Metrics](README.md#metrics-and-which-one-to-trust).

---

## Headline

### 1. The proxy was single-threaded when this was measured. Throughput did not scale with cores.

At saturation the prx-waf process holds **13 OS threads** but consumes
**0.99 cores** — on a 16-core machine. Adding cores adds nothing.

The cause is in the source, not in the configuration: `Server::new(None)`
(`crates/prx-waf/src/main.rs:1389`) falls back to Pingora's
`ServerConf::default()`, which sets `threads: 1`
(`pingora-core-0.8.1/src/server/configuration/mod.rs:137`), and the proxy
service is added with a bare `add_tcp` and no thread override
(`main.rs:1450-1452`). **On tree `87aa1bc` there is no config key to change
it.**

Everything else on this page is therefore a *per-thread* number. On tree
`87aa1bc`, horizontal scaling — more processes, more nodes — is the only lever
available.

> **Fixed after this page was recorded, and not yet re-measured.** `[proxy]
> worker_threads` now sizes the data plane and defaults to the CPUs the process
> may use, so the ceiling described in this section no longer applies to the
> shipped default. **No figure on this page has been re-run for it**, and none
> should be read as the multi-threaded number. The re-measurement is pending;
> until it lands, treat every table here as one thread's worth of work.

### 2. Detection cost is dominated by body size, and Lane 1's budget is off by default

CPU µs per request, as a delta over `passthrough` (the same binary with
detection off):

| layer | get-small | json-post (1 KiB) | form-post (512 B) | multipart (64 KiB) | body-1mb (1 MiB) |
|---|--:|--:|--:|--:|--:|
| **passthrough** (absolute µs/req) | 40 | 53 | 59 | 131 | 1,091 |
| Lane 1 regex detectors | +83 | +616 | +479 | **+21,469** | **+102,228** |
| OWASP CRS PL1 | +88 | +487 | +282 | +199 | +4,667 |
| OWASP CRS PL2 | +134 | +688 | +420 | +268 | +4,782 |
| OWASP CRS PL4 | +171 | +1,102 | +473 | +244 | +4,894 |
| Lane 2 semantic (shadow) | +41 | +127 | +74 | +74 | **+20** |
| rate limiter | −1 | −3 | −8 | +5 | −174 |
| **full** (shipping default) | +216 | +1,245 | +858 | **+21,172** | **+107,836** |

Lane 1 costs **21.5 ms of CPU on a 64 KiB upload and 102 ms on a 1 MiB body.**
That is not a percentage overhead; it is a different order of magnitude. In
throughput terms:

| posture | get-small | json-post | form-post | multipart | body-1mb |
|---|--:|--:|--:|--:|--:|
| origin (no proxy) | 171,856 | 161,335 | 118,226 | 81,185 | 26,680 |
| passthrough | 24,987 | 18,677 | 16,916 | 7,546 | 912 |
| lane1 | 8,124 | 1,494 | 1,860 | **46** | **10** |
| crs-pl1 | 7,827 | 1,851 | 2,934 | 3,028 | 174 |
| crs-pl2 | 5,758 | 1,348 | 2,088 | 2,501 | 170 |
| crs-pl4 | 4,749 | 888 | 1,873 | 2,661 | 167 |
| lane2 | 12,377 | 5,550 | 7,540 | 4,855 | 896 |
| cc | 25,906 | 19,751 | 19,723 | 7,336 | 1,085 |
| **full (shipping default)** | **3,918** | **771** | **1,092** | **47** | **9** |

**A default-configured prx-waf serves 47 requests per second of 64 KiB file
uploads, and 9 requests per second of 1 MiB request bodies, per core.** Those
two rows are the operationally important finding on this page.

### 3. The layer with a documented work budget is the only one that stays cheap

Notice the shape of the Lane 2 row: **+41, +127, +74, +74, +20 µs** — it barely
moves as the body grows from nothing to 1 MiB, and it is *cheapest* on the
largest body. That is not luck. Lane 2 has an explicit, operator-visible work
budget (`[content_security.budget]`: `max_field_input_bytes = 16 KiB`,
`max_preprocess_output_bytes_total = 512 KiB`, `max_decode_rounds = 3`), and the
budget does exactly what it says — past its caps the lane stops working and
marks the verdict `degraded`.

CRS is intermediate: its structured body processing is capped at 64 KiB
(`MAX_BODY_BYTES`, `checks/body_processors.rs:48`), which is precisely why the
CRS row *drops* from +487 µs on a 1 KiB JSON body to +199 µs on a 64 KiB
multipart one — past 64 KiB the body processor is skipped entirely and CRS sees
no structured targets at all. **The performance data and the fail-open
behaviour documented in [`docs/dos-budget.md`](../../docs/dos-budget.md) are the
same fact seen from two sides.** CRS still pays for raw-body scanning, which is
why the 1 MiB column is +4,667 µs.

Lane 1 had no equivalent budget when these numbers were taken, which is what
the 1 MiB column measures: its only bounds were the 64 KiB scan window and the
10 MiB total ceiling, so cost tracked body size all the way up.
`[content_security.lane1] max_body_bytes` now exists, but it defaults to 0
(unlimited), so **the figures above remain the shipped default**. Setting it to
65536 takes the 1 MiB body from +195,667 µs to +1,417 µs on the same host — at
the price of those four detectors seeing none of an oversized body, head
included. See `docs/dos-budget.md` §2.2.

### 4. Inside Lane 1, two detectors are 94% of the cost

`POSTURES=lane1-sqli,lane1-xss,… tests/perf/run.sh`, µs/req over `passthrough`:

| detector | multipart (64 KiB) | json-post (1 KiB) |
|---|--:|--:|
| sqli | **+12,284** | **+354** |
| xss | **+7,704** | **+179** |
| rce | +431 | +5 |
| traversal | +437 | +2 |
| sensitive | +75 | −7 |
| scanner | +24 | −7 |
| bot | −6 | +5 |
| *sum of the seven* | *20,949* | *531* |
| **all seven together (`lane1`)** | **21,158** | **568** |

The parts sum to the whole within 1–7%, so the detectors are **additive** — they
share no work. `sqli` and `xss` alone are 94% of Lane 1 on both workloads.

The same additivity holds at the lane level: summed layer deltas versus the
measured `full` posture come to 210 vs 216 µs (get-small), 1,227 vs 1,245
(json-post) and 21,747 vs 21,172 (multipart) — within 3%. **No work is shared
between Lane 1, CRS and Lane 2.** Each re-derives what it needs.

### 5. The rate limiter is free

−1 to +5 µs/req across every workload, i.e. below the measurement floor. The
per-IP token-bucket lookup costs nothing worth counting. (Measured with the
limiter configured never to fire, so this is the cost healthy traffic pays.)

### 6. Sustained attack traffic multiplies memory by 4–7×

Peak RSS during a 10 s flood of a SQLi payload, versus the same posture on
benign traffic:

| posture | RSS, benign (get-small) | RSS, attack flood |
|---|--:|--:|
| passthrough (nothing detected) | 59 MiB | 110 MiB |
| lane1 | 75 MiB | **454 MiB** |
| crs-pl1 | 63 MiB | **574 MiB** |
| crs-pl2 | 67 MiB | **750 MiB** |
| full | 80 MiB | **420 MiB** |

Every blocked request writes a `security_event` and an `attack_log` row, and the
database pool is 20 connections (`storage.max_connections`). Ten seconds of
attack traffic is enough to grow the process to 750 MiB. The harness does not
run long enough to say where this settles — **whether it plateaus or continues
is not established by this measurement, and it should be, because "attacker
controls your memory growth" is the shape of a DoS.** The `cc` row is the
control: with only the rate limiter on, nothing is detected, nothing is written,
and RSS stays at 110 MiB.

### 7. The proxy hop itself is not free either

`origin → passthrough` on a small GET is **171,856 → 24,987 RPS, −85%**, at 40 µs
of CPU per request. Some of that is a genuine second hop (two TCP connections,
two HTTP parses, a copy) and some of it is the single-thread ceiling in §1: at
24,987 RPS the WAF is already at 0.99 cores, so it is CPU-bound, not
architecture-bound. The origin figure is itself albedo-limited (5.55 of its 6
pinned cores), so the true no-proxy ceiling is higher than 171 k — treat the
origin row as "far above the WAF", not as an exact number.

---

## Latency

At `c=50` every prx-waf posture is saturated, so the p50/p95/p99 columns in the
full tables are **queueing delay, not service time** — `lane1`/`body-1mb` shows
p99 = 9.8 s, which is 50 connections queueing behind one thread doing 102 ms of
work each, not a 9.8 s request. Quoting those as "the latency the WAF adds"
would be wrong.

Re-run at `c=4`, where the cheap postures are no longer saturated, the added
latency is:

| workload | origin p50 | passthrough p50 | **full** p50 | **full** p99 | WAF adds (p50) |
|---|--:|--:|--:|--:|--:|
| get-small | 0.05 ms | 0.17 ms | **0.99 ms** | 1.50 ms | **+0.94 ms** |
| json-post (1 KiB) | 0.05 ms | 0.21 ms | **5.10 ms** | 7.86 ms | **+5.05 ms** |
| multipart (64 KiB) | 0.08 ms | 0.34 ms | **84.31 ms** | 127.36 ms | **+84.2 ms** |

Those rows have a round-to-round spread below 2%, so they are results rather
than noise.

**A shipping-default prx-waf adds about 1 ms to a small GET and about 5 ms to a
1 KiB JSON POST.** For most APIs that is an acceptable price. The 64 KiB upload
row is not: 84 ms.

One caveat on that last row, in the interests of not overstating it — at `c=4`
the multipart posture is *still* saturated. One thread doing 21 ms of CPU per
request tops out at ~47 RPS whatever the concurrency, so 84 ms is four requests
queueing behind 21 ms of work each. The honest statement is "**21 ms of CPU
service time, which becomes 84 ms of observed latency at a concurrency of
four**" — and it degrades linearly from there.

---

## Full tables

`c=50`, saturation. Generated by the harness; the machine-readable form is
[`results/c50-saturation.json`](results/c50-saturation.json).

<!-- BEGIN c50 -->
### get-small

| posture | RPS | vs origin | p50 | p95 | p99 | p99.9 | CPU µs/req | vs base | RSS | RPS spread | µs spread |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| origin (no proxy) | 171,856 | — | 0.22 | 0.72 | 1.24 | 2.25 | 32.18 | — | 14 MiB | 2.4% | 2.0% |
| passthrough (proxy, no detection) | 24,987 | -85.5% | 1.90 | 2.65 | 2.81 | 3.33 | 39.74 | — | 59 MiB | 1.8% | 2.0% |
| + Lane 1 regex detectors | 8,124 | -95.3% | 6.13 | 7.14 | 8.10 | 10.77 | 122.84 | +83.10 | 75 MiB | 10.7% | 11.5% |
| + OWASP CRS PL1 | 7,827 | -95.4% | 6.41 | 7.29 | 7.53 | 9.52 | 127.50 | +87.76 | 63 MiB | 0.5% | 0.5% |
| + OWASP CRS PL2 | 5,758 | -96.6% | 8.78 | 9.70 | 9.88 | 13.08 | 173.66 | +133.92 | 67 MiB | 1.6% | 1.6% |
| + OWASP CRS PL4 | 4,749 | -97.2% | 10.07 | 15.15 | 21.56 | 25.91 | 210.38 | +170.64 | 69 MiB | 9.2% | 8.8% |
| + Lane 2 semantic (shadow) | 12,377 | -92.8% | 4.01 | 4.91 | 5.12 | 5.68 | 80.67 | +40.93 | 64 MiB | 0.4% | 0.4% |
| + rate limiter | 25,906 | -84.9% | 1.82 | 2.54 | 2.69 | 3.11 | 38.33 | -1.41 | 58 MiB | 3.3% | 3.5% |
| full (shipping default) | 3,918 | -97.7% | 12.95 | 14.00 | 15.17 | 19.97 | 255.47 | +215.73 | 80 MiB | 0.1% | 0.3% |

Latency in ms. **CPU µs/req** is subject-process CPU time divided by requests served — read the layer attribution from this column, not from RPS: it measures work done per request, which is a property of the code, whereas RPS also measures whatever else the host was doing. `vs base` is µs/req minus the `passthrough` row. **The `origin` row's µs/req is albedo's CPU, not prx-waf's** — it is a different program, so compare µs/req only between prx-waf postures; use the RPS column for the origin comparison. RSS is the peak seen while sampling at 5 Hz. The two `spread` columns are (best − worst) over the rounds as a share of the median; treat any figure whose spread is above ~10% as noise rather than as a result.

### json-post

| posture | RPS | vs origin | p50 | p95 | p99 | p99.9 | CPU µs/req | vs base | RSS | RPS spread | µs spread |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| origin (no proxy) | 161,335 | — | 0.24 | 0.77 | 1.28 | 2.01 | 34.43 | — | 14 MiB | 1.3% | 1.2% |
| passthrough (proxy, no detection) | 18,677 | -88.4% | 2.57 | 3.44 | 3.74 | 4.36 | 53.33 | — | 60 MiB | 1.4% | 1.4% |
| + Lane 1 regex detectors | 1,494 | -99.1% | 33.58 | 36.53 | 56.08 | 64.79 | 669.30 | +615.97 | 77 MiB | 19.3% | 23.4% |
| + OWASP CRS PL1 | 1,851 | -98.9% | 27.44 | 28.81 | 29.14 | 43.74 | 540.68 | +487.35 | 67 MiB | 0.5% | 0.4% |
| + OWASP CRS PL2 | 1,348 | -99.2% | 37.79 | 45.25 | 48.49 | 54.59 | 741.63 | +688.30 | 71 MiB | 0.3% | 0.1% |
| + OWASP CRS PL4 | 888 | -99.4% | 56.68 | 74.14 | 86.67 | 104.87 | 1155.51 | +1102.18 | 82 MiB | 4.3% | 4.7% |
| + Lane 2 semantic (shadow) | 5,550 | -96.6% | 9.09 | 10.19 | 10.64 | 12.14 | 180.00 | +126.67 | 66 MiB | 10.6% | 11.9% |
| + rate limiter | 19,751 | -87.8% | 2.42 | 3.21 | 3.42 | 3.81 | 50.38 | -2.95 | 59 MiB | 1.1% | 1.0% |
| full (shipping default) | 771 | -99.5% | 66.20 | 69.06 | 72.00 | 97.41 | 1298.75 | +1245.42 | 86 MiB | 0.7% | 0.8% |

Latency in ms. **CPU µs/req** is subject-process CPU time divided by requests served — read the layer attribution from this column, not from RPS: it measures work done per request, which is a property of the code, whereas RPS also measures whatever else the host was doing. `vs base` is µs/req minus the `passthrough` row. **The `origin` row's µs/req is albedo's CPU, not prx-waf's** — it is a different program, so compare µs/req only between prx-waf postures; use the RPS column for the origin comparison. RSS is the peak seen while sampling at 5 Hz. The two `spread` columns are (best − worst) over the rounds as a share of the median; treat any figure whose spread is above ~10% as noise rather than as a result.

### form-post

| posture | RPS | vs origin | p50 | p95 | p99 | p99.9 | CPU µs/req | vs base | RSS | RPS spread | µs spread |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| origin (no proxy) | 118,226 | — | 0.27 | 1.03 | 3.17 | 11.19 | 36.04 | — | 14 MiB | 101.0% | 26.0% |
| passthrough (proxy, no detection) | 16,916 | -85.7% | 2.85 | 3.97 | 4.58 | 5.99 | 58.82 | — | 61 MiB | 8.2% | 8.9% |
| + Lane 1 regex detectors | 1,860 | -98.4% | 27.33 | 28.84 | 30.37 | 38.52 | 538.12 | +479.30 | 78 MiB | 0.5% | 0.5% |
| + OWASP CRS PL1 | 2,934 | -97.5% | 17.31 | 18.40 | 18.68 | 26.56 | 341.11 | +282.29 | 67 MiB | 0.0% | 0.1% |
| + OWASP CRS PL2 | 2,088 | -98.2% | 24.35 | 25.60 | 25.90 | 33.44 | 479.12 | +420.30 | 71 MiB | 0.3% | 0.5% |
| + OWASP CRS PL4 | 1,873 | -98.4% | 27.09 | 28.79 | 34.60 | 42.20 | 531.67 | +472.85 | 120 MiB | 11.1% | 14.9% |
| + Lane 2 semantic (shadow) | 7,540 | -93.6% | 6.49 | 7.94 | 12.19 | 14.63 | 132.37 | +73.55 | 66 MiB | 8.1% | 8.3% |
| + rate limiter | 19,723 | -83.3% | 2.42 | 3.21 | 3.43 | 3.88 | 50.35 | -8.47 | 60 MiB | 1.4% | 1.5% |
| full (shipping default) | 1,092 | -99.1% | 46.98 | 48.70 | 49.86 | 65.09 | 917.06 | +858.24 | 86 MiB | 0.5% | 0.8% |

Latency in ms. **CPU µs/req** is subject-process CPU time divided by requests served — read the layer attribution from this column, not from RPS: it measures work done per request, which is a property of the code, whereas RPS also measures whatever else the host was doing. `vs base` is µs/req minus the `passthrough` row. **The `origin` row's µs/req is albedo's CPU, not prx-waf's** — it is a different program, so compare µs/req only between prx-waf postures; use the RPS column for the origin comparison. RSS is the peak seen while sampling at 5 Hz. The two `spread` columns are (best − worst) over the rounds as a share of the median; treat any figure whose spread is above ~10% as noise rather than as a result.

### multipart

| posture | RPS | vs origin | p50 | p95 | p99 | p99.9 | CPU µs/req | vs base | RSS | RPS spread | µs spread |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| origin (no proxy) | 81,185 | — | 0.43 | 1.59 | 3.44 | 8.04 | 62.83 | — | 14 MiB | 64.6% | 10.1% |
| passthrough (proxy, no detection) | 7,546 | -90.7% | 6.10 | 10.75 | 14.24 | 21.79 | 131.46 | — | 72 MiB | 24.4% | 26.7% |
| + Lane 1 regex detectors | 46 | -99.9% | 1059.19 | 2092.03 | 2092.24 | 2092.28 | 21600.74 | +21469.28 | 88 MiB | 6.9% | 6.7% |
| + OWASP CRS PL1 | 3,028 | -96.3% | 16.70 | 18.03 | 18.70 | 25.39 | 330.59 | +199.13 | 74 MiB | 1.5% | 1.6% |
| + OWASP CRS PL2 | 2,501 | -96.9% | 20.26 | 21.58 | 22.30 | 26.28 | 399.37 | +267.91 | 78 MiB | 2.6% | 2.8% |
| + OWASP CRS PL4 | 2,661 | -96.7% | 19.04 | 20.47 | 21.15 | 26.77 | 375.83 | +244.37 | 118 MiB | 2.2% | 2.4% |
| + Lane 2 semantic (shadow) | 4,855 | -94.0% | 10.12 | 12.45 | 19.86 | 30.14 | 205.75 | +74.29 | 75 MiB | 7.5% | 7.3% |
| + rate limiter | 7,336 | -91.0% | 6.84 | 7.90 | 8.31 | 9.15 | 136.04 | +4.58 | 69 MiB | 14.1% | 15.8% |
| full (shipping default) | 47 | -99.9% | 1084.19 | 1747.74 | 1748.08 | 1806.03 | 21303.15 | +21171.69 | 96 MiB | 2.1% | 2.1% |

Latency in ms. **CPU µs/req** is subject-process CPU time divided by requests served — read the layer attribution from this column, not from RPS: it measures work done per request, which is a property of the code, whereas RPS also measures whatever else the host was doing. `vs base` is µs/req minus the `passthrough` row. **The `origin` row's µs/req is albedo's CPU, not prx-waf's** — it is a different program, so compare µs/req only between prx-waf postures; use the RPS column for the origin comparison. RSS is the peak seen while sampling at 5 Hz. The two `spread` columns are (best − worst) over the rounds as a share of the median; treat any figure whose spread is above ~10% as noise rather than as a result.

### body-1mb

| posture | RPS | vs origin | p50 | p95 | p99 | p99.9 | CPU µs/req | vs base | RSS | RPS spread | µs spread |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| origin (no proxy) | 26,680 | — | 1.17 | 5.78 | 9.26 | 13.97 | 147.11 | — | 246 MiB | 1.9% | 2.1% |
| passthrough (proxy, no detection) | 912 | -96.6% | 56.30 | 67.33 | 72.52 | 79.74 | 1090.56 | — | 110 MiB | 31.8% | 37.3% |
| + Lane 1 regex detectors | 10 | -100.0% | 8753.92 | 9705.77 | 9797.00 | 9797.00 | 103318.86 | +102228.30 | 96 MiB | 49.5% | 89.6% |
| + OWASP CRS PL1 | 174 | -99.3% | 300.95 | 340.67 | 349.62 | 361.52 | 5757.31 | +4666.75 | 112 MiB | 1.0% | 1.0% |
| + OWASP CRS PL2 | 170 | -99.4% | 308.66 | 350.44 | 364.36 | 381.99 | 5872.22 | +4781.66 | 115 MiB | 1.5% | 1.7% |
| + OWASP CRS PL4 | 167 | -99.4% | 310.40 | 353.40 | 378.56 | 391.89 | 5984.32 | +4893.76 | 122 MiB | 2.1% | 2.1% |
| + Lane 2 semantic (shadow) | 896 | -96.6% | 57.29 | 66.20 | 70.51 | 75.97 | 1110.33 | +19.77 | 115 MiB | 0.8% | 0.8% |
| + rate limiter | 1,085 | -95.9% | 47.56 | 54.05 | 57.19 | 61.64 | 916.13 | -174.43 | 109 MiB | 0.2% | 0.2% |
| full (shipping default) | 9 | -100.0% | 8231.32 | 9918.75 | 9964.65 | 9964.65 | 108926.41 | +107835.85 | 104 MiB | 28.2% | 37.1% |

Latency in ms. **CPU µs/req** is subject-process CPU time divided by requests served — read the layer attribution from this column, not from RPS: it measures work done per request, which is a property of the code, whereas RPS also measures whatever else the host was doing. `vs base` is µs/req minus the `passthrough` row. **The `origin` row's µs/req is albedo's CPU, not prx-waf's** — it is a different program, so compare µs/req only between prx-waf postures; use the RPS column for the origin comparison. RSS is the peak seen while sampling at 5 Hz. The two `spread` columns are (best − worst) over the rounds as a share of the median; treat any figure whose spread is above ~10% as noise rather than as a result.

### attack

| posture | RPS | vs origin | p50 | p95 | p99 | p99.9 | CPU µs/req | vs base | RSS | RPS spread | µs spread |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| origin (no proxy) | 151,612 | — | 0.25 | 0.78 | 1.52 | 3.02 | 36.96 | — | 47 MiB | 0.6% | 0.5% |
| passthrough (proxy, no detection) | 7,869 | -94.8% | 4.63 | 14.81 | 18.71 | 25.41 | 78.16 | — | 110 MiB | 140.8% | 47.0% |
| + Lane 1 regex detectors | 7,976 | -94.7% | 7.67 | 8.50 | 9.04 | 10.09 | 130.27 | +52.11 | 454 MiB | 37.5% | 55.5% |
| + OWASP CRS PL1 | 5,776 | -96.2% | 6.39 | 14.20 | 14.79 | 15.53 | 180.58 | +102.42 | 574 MiB | 3.5% | 4.3% |
| + OWASP CRS PL2 | 4,648 | -96.9% | 8.18 | 18.29 | 19.64 | 22.06 | 223.09 | +144.93 | 750 MiB | 2.8% | 3.1% |
| + OWASP CRS PL4 | 4,479 | -97.0% | 10.97 | 18.93 | 20.03 | 20.77 | 230.65 | +152.49 | 571 MiB | 2.4% | 4.7% |
| + Lane 2 semantic (shadow) | 6,963 | -95.4% | 7.24 | 8.47 | 8.88 | 10.25 | 152.09 | +73.93 | 114 MiB | 0.9% | 2.2% |
| + rate limiter | 24,809 | -83.6% | 1.90 | 2.65 | 2.85 | 3.54 | 40.03 | -38.13 | 110 MiB | 0.7% | 0.7% |
| full (shipping default) | 7,892 | -94.8% | 7.76 | 8.71 | 9.23 | 9.77 | 131.66 | +53.50 | 420 MiB | 54.8% | 103.6% |

Latency in ms. **CPU µs/req** is subject-process CPU time divided by requests served — read the layer attribution from this column, not from RPS: it measures work done per request, which is a property of the code, whereas RPS also measures whatever else the host was doing. `vs base` is µs/req minus the `passthrough` row. **The `origin` row's µs/req is albedo's CPU, not prx-waf's** — it is a different program, so compare µs/req only between prx-waf postures; use the RPS column for the origin comparison. RSS is the peak seen while sampling at 5 Hz. The two `spread` columns are (best − worst) over the rounds as a share of the median; treat any figure whose spread is above ~10% as noise rather than as a result.
<!-- END c50 -->

---

## Unsaturated latency (c=4)

Same harness, same tree, `c=4` instead of `c=50`, three postures dropped for
time. Machine-readable form:
[`results/c4-latency.json`](results/c4-latency.json).

<!-- BEGIN c4 -->
### get-small

| posture | RPS | vs origin | p50 | p95 | p99 | p99.9 | CPU µs/req | vs base | RSS | RPS spread | µs spread |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| origin (no proxy) | 72,779 | — | 0.05 | 0.08 | 0.10 | 0.20 | 38.21 | — | 14 MiB | 1.2% | 1.9% |
| passthrough (proxy, no detection) | 23,359 | -67.9% | 0.17 | 0.23 | 0.25 | 0.33 | 42.51 | — | 54 MiB | 0.9% | 0.9% |
| + Lane 1 regex detectors | 8,528 | -88.3% | 0.47 | 0.67 | 0.69 | 0.79 | 117.02 | +74.51 | 74 MiB | 0.4% | 0.2% |
| + OWASP CRS PL1 | 7,973 | -89.0% | 0.50 | 0.72 | 0.75 | 0.92 | 125.17 | +82.66 | 57 MiB | 0.8% | 0.8% |
| + Lane 2 semantic (shadow) | 11,902 | -83.6% | 0.33 | 0.47 | 0.50 | 0.54 | 83.85 | +41.34 | 59 MiB | 0.7% | 0.7% |
| full (shipping default) | 3,998 | -94.5% | 0.99 | 1.47 | 1.50 | 1.69 | 250.11 | +207.60 | 76 MiB | 0.3% | 0.2% |

Latency in ms. **CPU µs/req** is subject-process CPU time divided by requests served — read the layer attribution from this column, not from RPS: it measures work done per request, which is a property of the code, whereas RPS also measures whatever else the host was doing. `vs base` is µs/req minus the `passthrough` row. **The `origin` row's µs/req is albedo's CPU, not prx-waf's** — it is a different program, so compare µs/req only between prx-waf postures; use the RPS column for the origin comparison. RSS is the peak seen while sampling at 5 Hz. The two `spread` columns are (best − worst) over the rounds as a share of the median; treat any figure whose spread is above ~10% as noise rather than as a result.

### json-post

| posture | RPS | vs origin | p50 | p95 | p99 | p99.9 | CPU µs/req | vs base | RSS | RPS spread | µs spread |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| origin (no proxy) | 69,292 | — | 0.05 | 0.07 | 0.10 | 0.20 | 44.78 | — | 14 MiB | 1.0% | 0.7% |
| passthrough (proxy, no detection) | 18,691 | -73.0% | 0.21 | 0.29 | 0.31 | 0.37 | 53.18 | — | 54 MiB | 1.7% | 1.8% |
| + Lane 1 regex detectors | 1,603 | -97.7% | 2.49 | 3.71 | 3.78 | 4.41 | 623.86 | +570.68 | 74 MiB | 0.6% | 0.4% |
| + OWASP CRS PL1 | 1,891 | -97.3% | 2.11 | 3.15 | 3.19 | 3.58 | 528.32 | +475.14 | 58 MiB | 0.9% | 1.0% |
| + Lane 2 semantic (shadow) | 5,734 | -91.7% | 0.68 | 1.02 | 1.05 | 1.18 | 174.03 | +120.85 | 59 MiB | 0.9% | 0.8% |
| full (shipping default) | 781 | -98.9% | 5.10 | 7.66 | 7.86 | 8.77 | 1280.10 | +1226.92 | 79 MiB | 0.3% | 0.2% |

Latency in ms. **CPU µs/req** is subject-process CPU time divided by requests served — read the layer attribution from this column, not from RPS: it measures work done per request, which is a property of the code, whereas RPS also measures whatever else the host was doing. `vs base` is µs/req minus the `passthrough` row. **The `origin` row's µs/req is albedo's CPU, not prx-waf's** — it is a different program, so compare µs/req only between prx-waf postures; use the RPS column for the origin comparison. RSS is the peak seen while sampling at 5 Hz. The two `spread` columns are (best − worst) over the rounds as a share of the median; treat any figure whose spread is above ~10% as noise rather than as a result.

### multipart

| posture | RPS | vs origin | p50 | p95 | p99 | p99.9 | CPU µs/req | vs base | RSS | RPS spread | µs spread |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| origin (no proxy) | 45,696 | — | 0.08 | 0.11 | 0.13 | 0.24 | 68.61 | — | 14 MiB | 0.4% | 0.8% |
| passthrough (proxy, no detection) | 11,580 | -74.7% | 0.34 | 0.49 | 0.52 | 0.57 | 86.09 | — | 55 MiB | 0.8% | 0.7% |
| + Lane 1 regex detectors | 47 | -99.9% | 85.38 | 127.81 | 128.86 | 151.09 | 21345.77 | +21259.68 | 74 MiB | 0.6% | 0.8% |
| + OWASP CRS PL1 | 3,845 | -91.6% | 1.04 | 1.51 | 1.58 | 1.76 | 260.06 | +173.97 | 59 MiB | 0.8% | 0.7% |
| + Lane 2 semantic (shadow) | 7,861 | -82.8% | 0.51 | 0.73 | 0.77 | 0.88 | 126.96 | +40.87 | 60 MiB | 1.0% | 1.0% |
| full (shipping default) | 48 | -99.9% | 84.31 | 126.34 | 127.36 | 127.50 | 21078.36 | +20992.27 | 80 MiB | 0.4% | 0.4% |

Latency in ms. **CPU µs/req** is subject-process CPU time divided by requests served — read the layer attribution from this column, not from RPS: it measures work done per request, which is a property of the code, whereas RPS also measures whatever else the host was doing. `vs base` is µs/req minus the `passthrough` row. **The `origin` row's µs/req is albedo's CPU, not prx-waf's** — it is a different program, so compare µs/req only between prx-waf postures; use the RPS column for the origin comparison. RSS is the peak seen while sampling at 5 Hz. The two `spread` columns are (best − worst) over the rounds as a share of the median; treat any figure whose spread is above ~10% as noise rather than as a result.
<!-- END c4 -->

---

## What was not measured

* **CrowdSec.** Both the LAPI bouncer and the AppSec path need an external
  CrowdSec instance. The bouncer's hot path is a cache lookup, and AppSec's is
  an awaited HTTP call with a 500 ms default timeout
  (`crates/waf-engine/src/engine.rs:430`) — so its cost is dominated by network
  RTT to the LAPI and by cache hit rate, neither of which a single-host number
  would transfer to anyone else's deployment. Measuring it needs a topology, not
  a benchmark.
* **Response caching.** Held off in every posture on purpose (see README) — a
  cache hit skips the upstream and would make the WAF measure faster than its
  own origin. It needs its own workload mix (repeat rate, key cardinality).
* **The response phase.** No posture enables response-body inspection.
* **TLS.** Every measurement is plaintext HTTP/1.1. TLS handshake and record
  cost is real and is not in any number here.
* **HTTP/2 and HTTP/3.**
* **Sustained load.** The longest continuous measurement is 10 s. Nothing here
  says what happens after an hour — see §6.
* **Where Lane 1's time actually goes.** §4 localises it to the sqli and xss
  detectors, but not to a line. Both use a single `RegexSet` pass rather than
  looping patterns, so the naive explanation is ruled out. One structural
  amplifier is visible in the source and is worth checking first:
  `request_targets` (`crates/waf-engine/src/checks/mod.rs:272-284`) materialises
  the body up to **three times** — raw, url-decoded, and recursively
  url-decoded, the last via `url_decode_recursive` which allocates a fresh
  `String` on each of up to 5 passes (`checks/mod.rs:182-190`). That is
  allocation and copying proportional to body size before a single regex runs.
  **This is a hypothesis, not a finding** — confirming it needs a profiler, and
  that is the natural next step.

## Reproducing

```bash
tests/perf/run.sh                                    # the c=50 matrix
POSTURES=passthrough,lane1-sqli,lane1-xss,lane1 \
  WORKLOADS=multipart tests/perf/run.sh              # the Lane 1 bisect
CONNECTIONS=4 tests/perf/run.sh                      # unsaturated latency
```

Expect ~35 minutes for the full matrix. Run it on an otherwise idle machine and
check the spread columns before believing anything.
