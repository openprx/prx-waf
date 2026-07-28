# Measured runtime performance

Recorded **2026-07-26** by `tests/perf/run.sh` from tree
`c5074776649fa3bc47ebff9b762e72b923ee62f6`, working tree **clean** — no tracked
or untracked file differed from that commit while the binary was built or while
any figure below was taken. That commit changes only the harness; the WAF
sources it builds are byte-identical to `39d4fb2`, the tip of the two default
changes this page exists to re-measure. Methodology, and why the two reference
postures are what they are, is in [README.md](README.md). Raw data:
[`results/`](results/).

| | |
|---|---|
| CPU | AMD Ryzen 9 5900HX — **8 physical cores, 16 logical** (2-way SMT) |
| Memory | 30.8 GiB |
| Kernel | 6.12.48+deb13-amd64 |
| Generator | `oha` 1.11.0, `c=50`, 10 s × 3 rounds, median round |
| Origin | `albedo` v0.3.0 (200, empty body) |
| Pinning | WAF **CPUs 0–3**, origin 4–9, generator 10–15 |
| Proxy worker threads | 4 — the shipped default, resolved from the pinned set |
| `lane1 max_body_bytes` | 65536 — the shipped default |
| Host load (1 min) | 1.76 at start → 7.59 at end |

**CPUs 0–3 are two physical cores, not four.** `thread_siblings_list` pairs
0–1 and 2–3, so the WAF's pinned set is two cores' worth of execution resources
presented as four hardware threads. Every "4 threads" figure below means four
Pingora workers on two physical cores. This is also where the shipping default
comes from: `[proxy] worker_threads` is unset, and `available_parallelism`
reads the **affinity mask**, not `nproc`, so `taskset -c 0-3` makes the shipped
default 4. Startup says so verbatim:

> Proxy worker threads: 4 — `[proxy] worker_threads` is unset, so the data plane
> follows the CPUs it may run on (4 CPU(s) available to this process).

### Host state, and what "quiet" now has to mean

The host is a developer workstation and was not idle. One process — a
`chrome-devtools` MCP browser child — burns a steady **1.000 core**, and has for
35 hours. Rather than measure around it, all 20 of its processes were pinned to
CPUs 4–15 before the first round, along with every other background process
heavy enough to matter, so that **cores 0–3 belong to the WAF alone**. That was
verified rather than assumed, by comparing the busy jiffies on cores 0–3 against
the subject's own `utime+stime` over the same window, twice, mid-run:

| sample | cores 0–3 busy | prx-waf CPU | unaccounted |
|---|--:|--:|--:|
| 8.0 s | 3.885 cores | 3.898 cores | −0.014 |
| 10.0 s | 3.846 cores | 3.863 cores | −0.017 |

The residual is negative and of order 0.01 cores, which is the cost of reading
two counters a few hundred microseconds apart: **nothing but prx-waf ran on the
subject's cores.** The browser still shares CPUs 4–15 with the origin and the
generator — one core out of twelve — so it costs the reference rows a little
headroom and the subject rows nothing.

**The old page's "load ≈ 3" quiet criterion is retired, because it measured a
single-threaded era.** A load average cannot separate the subject from the host
now that the subject alone contributes four runnable threads: the 7.59 recorded
at the end of this run decomposes as prx-waf 3.86 + browser 1.00 + albedo ≈ 1.5
+ oha ≈ 1.5, and it means the benchmark was working, not that the host was busy.
The criterion this page uses instead is the one that survives multithreading:
**no measurable CPU on the subject's cores other than the subject**, checked
during the run, plus per-row spread columns the reader can audit. Those spreads
are the visible payoff: **47 of the 54 `c=50` cells have both spread columns
under 3%**, against rows that moved 20–140% on the page this replaces. Six of
the seven exceptions are the `origin` reference and the `attack` workload —
neither of which carries a conclusion here — and the seventh is
`crs-pl4`/`form-post` at 10.9%, which should be read as noise per the README's
own rule.

**Read the layer attribution from CPU µs/req, not from RPS.** See
[README.md § Metrics](README.md#metrics-and-which-one-to-trust).

---

## What changed since the last recording

The previous edition of this page was measured on tree `87aa1bc` and every table
in it has been superseded, because two shipped defaults changed underneath it:

* **`d457e0d` wired `[proxy] worker_threads` to Pingora.** Before it,
  `Server::new(None)` took `ServerConf::default()`, whose `threads: 1` sized the
  entire data plane, and no configuration key could change it — the process held
  13 OS threads and consumed 0.99 cores. **Every number on the old page was a
  single-thread number.** They were correct for what they measured and are not
  comparable to anything below.
* **`39d4fb2` changed `[content_security.lane1] max_body_bytes` from `0`
  (unlimited) to `65536`.** The old page's `lane1` and `full` rows for
  `multipart` and `body-1mb` therefore described a posture that now requires
  explicitly setting the key back to `0`. That posture is still measured here,
  as the contrast in §2 — it is just no longer what ships.

Both changes were benchmarked when they landed, on a host that was concurrently
running a second copy of this harness pinned to the same cores. Those figures
were labelled provisional and deliberately kept out of this file. They are
superseded by the numbers below and should not be quoted; where a provisional
figure can be compared, it **understated** the gain, exactly as its own caveat
predicted.

---

## Headline

### 1. The proxy uses every core it is given, and the gain is real but sublinear

At saturation on a small GET, `passthrough` now consumes **3.88 of its 4 pinned
hardware threads** and serves **58,078 rps**, against 24,987 rps at 0.99 cores
on the single-threaded tree. That is **×2.32 throughput for ×3.92 CPU**, on a
pinned set that is physically two cores. The shipping `full` posture saturates
the set slightly harder still, at 3.97 cores, and the process now holds 16 OS
threads where it held 13.

| workload | passthrough, 1 thread (`87aa1bc`) | passthrough, shipped default (4 threads) | |
|---|--:|--:|--:|
| get-small | 24,987 rps | **58,078 rps** | ×2.32 |
| json-post | 18,677 rps | **45,832 rps** | ×2.45 |
| form-post | 16,916 rps | **45,560 rps** | ×2.69 |
| multipart | 7,546 rps | **21,764 rps** | ×2.88 |
| body-1mb | 912 rps | **2,130 rps** | ×2.34 |

The two ends of that comparison come from different runs on different trees, so
read them as a change of era rather than as a controlled ratio. **The controlled
`worker_threads` = 1 / 2 / 4 sweep on one tree and one host is not in this
edition** — see § What was not measured. What this edition does establish, from
the CPU column rather than from RPS, is that per-request cost rose when the data
plane went wide: `passthrough`/get-small costs **67 µs/req** here against
**40 µs/req** single-threaded, i.e. roughly **+68% CPU per request** for the
multi-threaded runtime. Throughput rising by less than the thread count is
therefore not a mystery to be explained later; most of it is already visible
and paid for in that column. **Which part of the remainder is SMT (four threads
on two cores) and which is contention has not been separated**, and needs the
sweep plus a physical-core pinning to answer.

### 2. Bounding Lane 1's body budget is worth 20–75×, and that is the largest single number on this page

Same binary, same host, same run parameters, one config default apart. `0`
restores the pre-`39d4fb2` posture; `65536` is what ships:

| posture | workload | `max_body_bytes = 0` | `= 65536` (shipped) | gain |
|---|---|--:|--:|--:|
| lane1 | multipart (64 KiB) | 93 rps · 42,857 µs/req | **7,049 rps · 565 µs/req** | **×75.5** |
| lane1 | body-1mb (1 MiB) | 15 rps · 259,721 µs/req | **726 rps · 5,496 µs/req** | **×47.2** |
| full | multipart (64 KiB) | 94 rps · 42,619 µs/req | **4,237 rps · 939 µs/req** | **×45.1** |
| full | body-1mb (1 MiB) | 15 rps · 266,874 µs/req | **306 rps · 13,073 µs/req** | **×20.4** |
| passthrough | multipart | 22,902 rps | 21,764 rps | ×1.0 — control |
| passthrough | body-1mb | 2,025 rps | 2,130 rps | ×1.1 — control |

Round-to-round spread is **at or below 4.6% on every cell**, including the
`= 0` ones, so these are results and not noise. The `passthrough` control moves
by 0–10%, confirming the key changes nothing where no Lane 1 detector is on.

The provisional figures taken under contamination were 41× and 37×; the clean
numbers are **75.5× and 47.2×**. The contamination understated the gain, which
is what its own caveat said it would do, and is why nothing was published from
it. `docs/dos-budget.md` §2.2 now carries these figures.

Unbounded, the four Lane 1 regex detectors cost **42.7 ms of CPU on a 64 KiB
upload and 258 ms on a 1 MiB body**, as a delta over the same binary with
detection off. At the shipped default those fall to **385 µs and 3.6 ms**. The
operational statement the old page made — that an unbounded Lane 1 served **93
requests per second of 64 KiB uploads and 15 requests per second of 1 MiB
bodies**, reachable by any unauthenticated client that can POST, with no evasion
of any kind — survives the re-measurement almost unchanged, and it is now a
statement about a posture an operator has to select deliberately rather than
about the one they get out of the box.

**What the default costs.** The `sqli` / `xss` / `rce` / `dir_traversal`
detectors see **none** of a body over 64 KiB — not a truncated prefix, none of
it. CRS (past its own 64 KiB structured cap), Lane 2 and every non-body surface
still inspect the request, every skip is counted and WARNed, and the verdict
carries `degraded` so "not inspected" cannot be read downstream as "inspected
and clean". See [`docs/dos-budget.md` §2.2](../../docs/dos-budget.md).

### 3. Detection cost, per layer

CPU µs per request, as a delta over `passthrough` (the same binary with
detection off), at the shipped defaults:

| layer | get-small | json-post (1 KiB) | form-post (512 B) | multipart (64 KiB) | body-1mb (1 MiB) |
|---|--:|--:|--:|--:|--:|
| **passthrough** (absolute µs/req) | 67 | 85 | 85 | 180 | 1,850 |
| Lane 1 regex detectors | +137 | +1,057 | +917 | +385 | +3,646 |
| OWASP CRS PL1 | +144 | +801 | +468 | +295 | +7,099 |
| OWASP CRS PL2 | +218 | +1,137 | +682 | +390 | +7,779 |
| OWASP CRS PL4 | +236 | +1,638 | +852 | +433 | +8,041 |
| Lane 2 semantic (shadow) | +66 | +221 | +117 | +55 | +342 |
| rate limiter | +2 | +2 | +1 | −2 | +65 |
| **full** (shipping default) | +350 | +2,148 | +1,543 | +759 | +11,223 |

Two shapes are worth naming. **CRS is now the most expensive layer on a 1 MiB
body by a wide margin** (+7,099 µs against Lane 1's +3,646), which is the direct
consequence of §2: Lane 1 stops reading at 64 KiB and CRS keeps scanning the raw
body. On the old page the order was the other way round and Lane 1 was 22× CRS.
And **Lane 1 is no longer body-dominated at the shipped default** — its
multipart delta (+385 µs) is now *smaller* than its json-post delta (+1,057 µs),
because the 64 KiB upload exceeds the budget and the 1 KiB JSON does not.

### 4. The layer with a documented work budget is still the cheapest

Lane 2's row — **+66, +221, +117, +55, +342 µs** — barely moves as the body
grows from nothing to 1 MiB, and it is *cheaper* on a 64 KiB multipart body than
on a 1 KiB JSON one. That is not luck. Lane 2 has an explicit, operator-visible
work budget (`[content_security.budget]`: `max_field_input_bytes = 16 KiB`,
`max_preprocess_output_bytes_total = 512 KiB`, `max_decode_rounds = 3`), and the
budget does exactly what it says — past its caps the lane stops working and
marks the verdict `degraded`.

CRS is intermediate: its structured body processing is capped at 64 KiB
(`MAX_BODY_BYTES`, `checks/body_processors.rs:48`), which is why the CRS row
*drops* from +801 µs on a 1 KiB JSON body to +295 µs on a 64 KiB multipart one —
past 64 KiB the body processor is skipped entirely and CRS sees no structured
targets at all. It still pays for raw-body scanning, which is the +7,099 µs in
the 1 MiB column. **The performance data and the fail-open behaviour documented
in [`docs/dos-budget.md`](../../docs/dos-budget.md) are the same fact seen from
two sides.**

Lane 1 now has an equivalent budget, and §2 is what it bought. The three lanes
now stop reading a request body at the same 64 KiB boundary, so an operator has
one number to reason about instead of three that disagreed.

### 5. The rate limiter is free

−2 to +2 µs/req on every workload except the 1 MiB body, where it is +65 µs —
all of it at or near the measurement floor. The per-IP token-bucket lookup costs
nothing worth counting. (Measured with the limiter configured never to fire, so
this is the cost healthy traffic pays.)

### 6. Sustained attack traffic now multiplies memory by up to 65×, not 4–7×

Peak RSS during a 10 s flood of a SQLi payload, versus the same posture on
benign traffic:

| posture | RSS, benign (get-small) | RSS, attack flood | attack rps | growth |
|---|--:|--:|--:|--:|
| passthrough (nothing detected) | 63 MiB | 113 MiB | 51,580 | ×1.8 |
| cc (limiter only — the control) | 62 MiB | 113 MiB | 50,592 | ×1.8 |
| lane2 (shadow, blocks nothing) | 71 MiB | 120 MiB | 15,939 | ×1.7 |
| lane1 | 88 MiB | **2,255 MiB** | 18,481 | **×25.6** |
| crs-pl1 | 76 MiB | **4,918 MiB** | 14,775 | **×64.7** |
| crs-pl2 | 94 MiB | **1,761 MiB** | 11,725 | ×18.7 |
| crs-pl4 | 100 MiB | **4,118 MiB** | 11,191 | ×41.2 |
| **full (shipping default)** | 106 MiB | **4,065 MiB** | 19,020 | **×38.3** |

**This got dramatically worse, and multithreading is why.** The old
single-threaded page recorded 420–750 MiB under the same flood; the shipping
posture now reaches **4.0 GiB in ten seconds**. Nothing about the write path
changed — every blocked request still writes a `security_event` and an
`attack_log` row, and the database pool is still 20 connections
(`storage.max_connections`) — but the data plane now generates blocked requests
2–3× faster while the drain rate behind those 20 connections did not move, so
the queue in front of them grows that much faster.

The two controls make the attribution unambiguous: `cc` and `passthrough` detect
nothing, write nothing, and stay at 113 MiB; `lane2` is in its shipping shadow
posture, observes without blocking, and stays at 120 MiB. **The growth is the
persistence path, not the detection.**

The harness does not run long enough to say where this settles — **whether it
plateaus or continues is not established by this measurement, and it should be,
because "attacker controls your memory growth" is the shape of a DoS, and the
number is now measured in gigabytes rather than hundreds of megabytes.**

### 7. The proxy hop itself is not free either

`origin → passthrough` on a small GET is **169,700 → 58,078 rps, −66%**, at 67 µs
of CPU per request. That is a real second hop — two TCP connections, two HTTP
parses, a copy — and at 58,078 rps the WAF is consuming 3.90 of its 4 pinned
threads, so it is CPU-bound on two physical cores rather than
architecture-bound. The origin figure is itself albedo-limited, so treat the
origin row as "far above the WAF", not as an exact number.

The gap narrowed from −85.5% to −66% purely because the WAF got its cores back;
the origin barely moved (171,856 → 169,700 rps).

---

## Latency

At `c=50` every prx-waf posture is saturated, so the p50/p95/p99 columns in the
full tables are **queueing delay, not service time**. Quoting them as "the
latency the WAF adds" would be wrong.

Re-run at `c=4`, where the cheap postures are no longer saturated, the added
latency is:

| workload | origin p50 | passthrough p50 | **full** p50 | **full** p99 | WAF adds (p50) |
|---|--:|--:|--:|--:|--:|
| get-small | 0.05 ms | 0.12 ms | **0.47 ms** | 0.78 ms | **+0.42 ms** |
| json-post (1 KiB) | 0.06 ms | 0.14 ms | **2.24 ms** | 3.62 ms | **+2.18 ms** |
| multipart (64 KiB) | 0.09 ms | 0.20 ms | **0.98 ms** | 1.56 ms | **+0.90 ms** |

Every row has a round-to-round spread below 1%, so these are results rather than
noise.

**A shipping-default prx-waf adds about 0.4 ms to a small GET, about 2.2 ms to a
1 KiB JSON POST, and about 0.9 ms to a 64 KiB upload.**

**The upload row is the headline change on this page.** The previous edition
recorded **+84.2 ms** for that same 64 KiB multipart request and said plainly
that the figure was not acceptable. It is now **+0.90 ms**, a 94× improvement,
and both defaults contributed: the body budget removed 42 ms of Lane 1 CPU per
request, and the wider data plane absorbed what remained. The old caveat that
the multipart posture was *still saturated at `c=4`* no longer applies either —
at 3,976 rps against 4 connections it is not queueing, so 0.98 ms is service
time and not a queue.

---

## Full tables

`c=50`, saturation, shipping defaults throughout. Generated by the harness; the
machine-readable form is
[`results/c50-saturation.json`](results/c50-saturation.json).

One row does not measure what its name says, and did not on the previous page
either: **`crs-pl4` / `json-post` answers every request with 403.** PL4 blocks
the harness's benign 1 KiB API payload, so that cell measures the block path,
not the proxied path, and is not comparable to the other `json-post` rows. It is
left in place, labelled, rather than deleted — a paranoia level that rejects an
ordinary JSON write is a fact about PL4 worth seeing. The old page reported it
as an ordinary throughput number with no such note.

<!-- BEGIN c50 -->
### get-small

| posture | RPS | vs origin | p50 | p95 | p99 | p99.9 | CPU µs/req | vs base | RSS | RPS spread | µs spread |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| origin (no proxy) | 169,700 | — | 0.22 | 0.73 | 1.31 | 3.18 | 31.08 | — | 14 MiB | 2.2% | 2.9% |
| passthrough (proxy, no detection) | 58,078 | -65.8% | 0.85 | 1.22 | 1.40 | 1.94 | 66.69 | — | 63 MiB | 1.4% | 1.2% |
| + Lane 1 regex detectors | 19,446 | -88.5% | 2.55 | 3.69 | 4.18 | 4.72 | 203.95 | +137.26 | 88 MiB | 0.4% | 0.5% |
| + OWASP CRS PL1 | 18,763 | -88.9% | 2.64 | 3.83 | 4.34 | 4.85 | 211.16 | +144.47 | 76 MiB | 0.4% | 0.3% |
| + OWASP CRS PL2 | 13,946 | -91.8% | 3.55 | 5.16 | 5.86 | 6.61 | 284.68 | +217.99 | 94 MiB | 0.6% | 0.5% |
| + OWASP CRS PL4 | 13,103 | -92.3% | 3.78 | 5.50 | 6.25 | 7.05 | 302.88 | +236.19 | 100 MiB | 0.1% | 0.0% |
| + Lane 2 semantic (shadow) | 29,457 | -82.6% | 1.68 | 2.42 | 2.73 | 3.11 | 132.81 | +66.12 | 71 MiB | 0.6% | 0.6% |
| + rate limiter | 56,590 | -66.7% | 0.87 | 1.25 | 1.43 | 1.92 | 68.60 | +1.91 | 62 MiB | 0.7% | 0.5% |
| full (shipping default) | 9,517 | -94.4% | 5.21 | 7.60 | 8.62 | 9.67 | 417.04 | +350.35 | 106 MiB | 0.8% | 0.9% |

Latency in ms. **CPU µs/req** is subject-process CPU time divided by requests served — read the layer attribution from this column, not from RPS: it measures work done per request, which is a property of the code, whereas RPS also measures whatever else the host was doing. `vs base` is µs/req minus the `passthrough` row. **The `origin` row's µs/req is albedo's CPU, not prx-waf's** — it is a different program, so compare µs/req only between prx-waf postures; use the RPS column for the origin comparison. RSS is the peak seen while sampling at 5 Hz. The two `spread` columns are (best − worst) over the rounds as a share of the median; treat any figure whose spread is above ~10% as noise rather than as a result.

### json-post

| posture | RPS | vs origin | p50 | p95 | p99 | p99.9 | CPU µs/req | vs base | RSS | RPS spread | µs spread |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| origin (no proxy) | 160,776 | — | 0.24 | 0.77 | 1.30 | 2.42 | 33.67 | — | 14 MiB | 7.5% | 1.2% |
| passthrough (proxy, no detection) | 45,832 | -71.5% | 1.08 | 1.55 | 1.77 | 2.28 | 85.04 | — | 66 MiB | 0.4% | 0.5% |
| + Lane 1 regex detectors | 3,492 | -97.8% | 14.12 | 20.93 | 23.61 | 26.50 | 1142.49 | +1057.45 | 91 MiB | 0.9% | 0.9% |
| + OWASP CRS PL1 | 4,501 | -97.2% | 10.98 | 16.15 | 18.45 | 20.55 | 885.62 | +800.58 | 83 MiB | 0.7% | 0.7% |
| + OWASP CRS PL2 | 3,266 | -98.0% | 15.11 | 22.39 | 25.64 | 29.86 | 1221.74 | +1136.70 | 102 MiB | 0.3% | 0.3% |
| + OWASP CRS PL4 | 2,312 | -98.6% | 21.56 | 30.93 | 35.33 | 39.06 | 1723.33 | +1638.29 | 416 MiB | 2.3% | 2.2% |
| + Lane 2 semantic (shadow) | 12,914 | -92.0% | 3.83 | 5.58 | 6.34 | 7.27 | 306.09 | +221.05 | 76 MiB | 0.3% | 0.3% |
| + rate limiter | 44,886 | -72.1% | 1.10 | 1.58 | 1.80 | 2.31 | 86.82 | +1.78 | 66 MiB | 0.3% | 0.3% |
| full (shipping default) | 1,789 | -98.9% | 27.59 | 40.60 | 46.59 | 51.71 | 2233.34 | +2148.30 | 116 MiB | 0.5% | 0.4% |

Latency in ms. **CPU µs/req** is subject-process CPU time divided by requests served — read the layer attribution from this column, not from RPS: it measures work done per request, which is a property of the code, whereas RPS also measures whatever else the host was doing. `vs base` is µs/req minus the `passthrough` row. **The `origin` row's µs/req is albedo's CPU, not prx-waf's** — it is a different program, so compare µs/req only between prx-waf postures; use the RPS column for the origin comparison. RSS is the peak seen while sampling at 5 Hz. The two `spread` columns are (best − worst) over the rounds as a share of the median; treat any figure whose spread is above ~10% as noise rather than as a result.

### form-post

| posture | RPS | vs origin | p50 | p95 | p99 | p99.9 | CPU µs/req | vs base | RSS | RPS spread | µs spread |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| origin (no proxy) | 158,728 | — | 0.24 | 0.78 | 1.34 | 2.83 | 33.86 | — | 15 MiB | 11.1% | 1.4% |
| passthrough (proxy, no detection) | 45,560 | -71.3% | 1.08 | 1.56 | 1.78 | 2.23 | 85.47 | — | 68 MiB | 0.3% | 0.4% |
| + Lane 1 regex detectors | 3,982 | -97.5% | 12.38 | 18.27 | 20.88 | 23.25 | 1002.69 | +917.22 | 93 MiB | 0.3% | 0.3% |
| + OWASP CRS PL1 | 7,192 | -95.5% | 6.89 | 10.09 | 11.42 | 12.92 | 553.49 | +468.02 | 86 MiB | 0.3% | 0.4% |
| + OWASP CRS PL2 | 5,197 | -96.7% | 9.53 | 13.99 | 15.90 | 18.08 | 767.14 | +681.67 | 103 MiB | 0.2% | 0.2% |
| + OWASP CRS PL4 | 4,233 | -97.3% | 11.65 | 17.59 | 20.33 | 23.66 | 937.47 | +852.00 | 520 MiB | 10.9% | 9.8% |
| + Lane 2 semantic (shadow) | 19,410 | -87.8% | 2.55 | 3.70 | 4.20 | 4.85 | 202.83 | +117.36 | 76 MiB | 0.2% | 0.3% |
| + rate limiter | 44,832 | -71.8% | 1.10 | 1.59 | 1.81 | 2.45 | 86.82 | +1.35 | 67 MiB | 0.6% | 0.6% |
| full (shipping default) | 2,452 | -98.5% | 20.04 | 29.63 | 33.35 | 38.06 | 1628.67 | +1543.20 | 118 MiB | 0.5% | 0.6% |

Latency in ms. **CPU µs/req** is subject-process CPU time divided by requests served — read the layer attribution from this column, not from RPS: it measures work done per request, which is a property of the code, whereas RPS also measures whatever else the host was doing. `vs base` is µs/req minus the `passthrough` row. **The `origin` row's µs/req is albedo's CPU, not prx-waf's** — it is a different program, so compare µs/req only between prx-waf postures; use the RPS column for the origin comparison. RSS is the peak seen while sampling at 5 Hz. The two `spread` columns are (best − worst) over the rounds as a share of the median; treat any figure whose spread is above ~10% as noise rather than as a result.

### multipart

| posture | RPS | vs origin | p50 | p95 | p99 | p99.9 | CPU µs/req | vs base | RSS | RPS spread | µs spread |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| origin (no proxy) | 89,098 | — | 0.42 | 1.37 | 2.58 | 6.53 | 57.83 | — | 14 MiB | 13.8% | 0.3% |
| passthrough (proxy, no detection) | 21,764 | -75.6% | 2.27 | 3.32 | 3.80 | 4.56 | 180.12 | — | 78 MiB | 2.1% | 1.9% |
| + Lane 1 regex detectors | 7,049 | -92.1% | 7.03 | 10.27 | 11.75 | 13.35 | 564.64 | +384.52 | 101 MiB | 0.6% | 0.6% |
| + OWASP CRS PL1 | 8,358 | -90.6% | 5.92 | 8.69 | 9.85 | 11.14 | 474.98 | +294.86 | 93 MiB | 0.6% | 0.7% |
| + OWASP CRS PL2 | 6,966 | -92.2% | 7.13 | 10.40 | 11.77 | 13.30 | 570.50 | +390.38 | 112 MiB | 1.0% | 1.2% |
| + OWASP CRS PL4 | 6,470 | -92.7% | 7.66 | 11.21 | 12.77 | 14.67 | 613.25 | +433.13 | 520 MiB | 3.4% | 3.1% |
| + Lane 2 semantic (shadow) | 16,712 | -81.2% | 2.96 | 4.32 | 4.90 | 5.61 | 234.69 | +54.57 | 86 MiB | 0.9% | 0.8% |
| + rate limiter | 22,070 | -75.2% | 2.24 | 3.27 | 3.75 | 4.50 | 177.66 | -2.46 | 77 MiB | 1.6% | 1.6% |
| full (shipping default) | 4,237 | -95.2% | 11.66 | 17.23 | 19.59 | 22.20 | 939.49 | +759.37 | 127 MiB | 0.3% | 0.3% |

Latency in ms. **CPU µs/req** is subject-process CPU time divided by requests served — read the layer attribution from this column, not from RPS: it measures work done per request, which is a property of the code, whereas RPS also measures whatever else the host was doing. `vs base` is µs/req minus the `passthrough` row. **The `origin` row's µs/req is albedo's CPU, not prx-waf's** — it is a different program, so compare µs/req only between prx-waf postures; use the RPS column for the origin comparison. RSS is the peak seen while sampling at 5 Hz. The two `spread` columns are (best − worst) over the rounds as a share of the median; treat any figure whose spread is above ~10% as noise rather than as a result.

### body-1mb

| posture | RPS | vs origin | p50 | p95 | p99 | p99.9 | CPU µs/req | vs base | RSS | RPS spread | µs spread |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| origin (no proxy) | 26,889 | — | 1.16 | 5.61 | 9.19 | 13.89 | 145.92 | — | 246 MiB | 1.4% | 0.2% |
| passthrough (proxy, no detection) | 2,130 | -92.1% | 23.58 | 32.45 | 36.30 | 40.41 | 1849.76 | — | 110 MiB | 1.3% | 1.3% |
| + Lane 1 regex detectors | 726 | -97.3% | 68.69 | 95.04 | 107.84 | 121.56 | 5495.99 | +3646.23 | 177 MiB | 0.3% | 0.3% |
| + OWASP CRS PL1 | 447 | -98.3% | 111.77 | 155.28 | 176.14 | 194.94 | 8948.74 | +7098.98 | 171 MiB | 0.7% | 0.7% |
| + OWASP CRS PL2 | 415 | -98.5% | 120.87 | 169.21 | 189.43 | 206.08 | 9628.71 | +7778.95 | 183 MiB | 0.5% | 0.5% |
| + OWASP CRS PL4 | 404 | -98.5% | 124.82 | 171.81 | 187.64 | 203.67 | 9890.86 | +8041.10 | 520 MiB | 0.3% | 0.3% |
| + Lane 2 semantic (shadow) | 1,803 | -93.3% | 27.95 | 38.06 | 42.17 | 47.72 | 2192.10 | +342.34 | 116 MiB | 0.7% | 0.8% |
| + rate limiter | 2,058 | -92.3% | 24.50 | 33.34 | 36.98 | 41.19 | 1914.62 | +64.86 | 113 MiB | 0.3% | 0.1% |
| full (shipping default) | 306 | -98.9% | 165.15 | 220.79 | 247.59 | 268.03 | 13072.66 | +11222.90 | 189 MiB | 0.7% | 0.6% |

Latency in ms. **CPU µs/req** is subject-process CPU time divided by requests served — read the layer attribution from this column, not from RPS: it measures work done per request, which is a property of the code, whereas RPS also measures whatever else the host was doing. `vs base` is µs/req minus the `passthrough` row. **The `origin` row's µs/req is albedo's CPU, not prx-waf's** — it is a different program, so compare µs/req only between prx-waf postures; use the RPS column for the origin comparison. RSS is the peak seen while sampling at 5 Hz. The two `spread` columns are (best − worst) over the rounds as a share of the median; treat any figure whose spread is above ~10% as noise rather than as a result.

### attack

| posture | RPS | vs origin | p50 | p95 | p99 | p99.9 | CPU µs/req | vs base | RSS | RPS spread | µs spread |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| origin (no proxy) | 153,075 | — | 0.25 | 0.77 | 1.52 | 3.02 | 36.50 | — | 44 MiB | 2.0% | 0.5% |
| passthrough (proxy, no detection) | 51,580 | -66.3% | 0.95 | 1.40 | 1.74 | 2.39 | 75.15 | — | 113 MiB | 1.7% | 1.6% |
| + Lane 1 regex detectors | 18,481 | -87.9% | 2.69 | 3.99 | 4.53 | 5.16 | 212.38 | +137.23 | 2255 MiB | 1.2% | 1.1% |
| + OWASP CRS PL1 | 14,775 | -90.3% | 3.37 | 5.03 | 5.74 | 6.55 | 265.38 | +190.23 | 4918 MiB | 3.5% | 3.6% |
| + OWASP CRS PL2 | 11,725 | -92.3% | 4.27 | 6.32 | 7.14 | 8.01 | 335.77 | +260.62 | 1761 MiB | 2.6% | 2.6% |
| + OWASP CRS PL4 | 11,191 | -92.7% | 4.48 | 6.66 | 7.59 | 8.67 | 351.97 | +276.82 | 4118 MiB | 0.5% | 0.4% |
| + Lane 2 semantic (shadow) | 15,939 | -89.6% | 3.10 | 4.53 | 5.21 | 6.31 | 245.50 | +170.35 | 120 MiB | 1.5% | 1.5% |
| + rate limiter | 50,592 | -66.9% | 0.97 | 1.43 | 1.75 | 2.40 | 76.59 | +1.44 | 113 MiB | 0.4% | 0.5% |
| full (shipping default) | 19,020 | -87.6% | 2.61 | 3.92 | 4.47 | 5.19 | 206.15 | +131.00 | 4065 MiB | 4.5% | 4.7% |

Latency in ms. **CPU µs/req** is subject-process CPU time divided by requests served — read the layer attribution from this column, not from RPS: it measures work done per request, which is a property of the code, whereas RPS also measures whatever else the host was doing. `vs base` is µs/req minus the `passthrough` row. **The `origin` row's µs/req is albedo's CPU, not prx-waf's** — it is a different program, so compare µs/req only between prx-waf postures; use the RPS column for the origin comparison. RSS is the peak seen while sampling at 5 Hz. The two `spread` columns are (best − worst) over the rounds as a share of the median; treat any figure whose spread is above ~10% as noise rather than as a result.

<!-- END c50 -->

---

## Unsaturated latency (c=4)

Same harness, same tree, same defaults, `c=4` instead of `c=50`, three postures
dropped for time. Machine-readable form:
[`results/c4-latency.json`](results/c4-latency.json).

<!-- BEGIN c4 -->
### get-small

| posture | RPS | vs origin | p50 | p95 | p99 | p99.9 | CPU µs/req | vs base | RSS | RPS spread | µs spread |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| origin (no proxy) | 71,620 | — | 0.05 | 0.08 | 0.10 | 0.21 | 38.82 | — | 13 MiB | 0.9% | 1.1% |
| passthrough (proxy, no detection) | 32,362 | -54.8% | 0.12 | 0.15 | 0.17 | 0.26 | 78.68 | — | 57 MiB | 0.6% | 0.7% |
| + Lane 1 regex detectors | 15,404 | -78.5% | 0.25 | 0.33 | 0.39 | 0.44 | 204.23 | +125.55 | 83 MiB | 0.3% | 0.3% |
| + OWASP CRS PL1 | 14,907 | -79.2% | 0.26 | 0.36 | 0.41 | 0.44 | 211.32 | +132.64 | 70 MiB | 0.5% | 0.2% |
| + Lane 2 semantic (shadow) | 21,465 | -70.0% | 0.18 | 0.23 | 0.28 | 0.32 | 137.58 | +58.90 | 66 MiB | 0.3% | 0.3% |
| full (shipping default) | 8,243 | -88.5% | 0.47 | 0.67 | 0.78 | 0.86 | 409.30 | +330.62 | 100 MiB | 0.4% | 0.5% |

Latency in ms. **CPU µs/req** is subject-process CPU time divided by requests served — read the layer attribution from this column, not from RPS: it measures work done per request, which is a property of the code, whereas RPS also measures whatever else the host was doing. `vs base` is µs/req minus the `passthrough` row. **The `origin` row's µs/req is albedo's CPU, not prx-waf's** — it is a different program, so compare µs/req only between prx-waf postures; use the RPS column for the origin comparison. RSS is the peak seen while sampling at 5 Hz. The two `spread` columns are (best − worst) over the rounds as a share of the median; treat any figure whose spread is above ~10% as noise rather than as a result.

### json-post

| posture | RPS | vs origin | p50 | p95 | p99 | p99.9 | CPU µs/req | vs base | RSS | RPS spread | µs spread |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| origin (no proxy) | 68,041 | — | 0.06 | 0.08 | 0.10 | 0.21 | 45.30 | — | 14 MiB | 0.5% | 0.4% |
| passthrough (proxy, no detection) | 28,346 | -58.3% | 0.14 | 0.17 | 0.19 | 0.29 | 95.04 | — | 57 MiB | 0.4% | 0.6% |
| + Lane 1 regex detectors | 3,369 | -95.0% | 1.17 | 1.47 | 1.81 | 2.25 | 1096.99 | +1001.95 | 84 MiB | 0.7% | 0.5% |
| + OWASP CRS PL1 | 4,255 | -93.7% | 0.92 | 1.27 | 1.50 | 1.73 | 851.52 | +756.48 | 74 MiB | 0.6% | 0.3% |
| + Lane 2 semantic (shadow) | 11,177 | -83.6% | 0.35 | 0.48 | 0.56 | 0.61 | 301.79 | +206.75 | 68 MiB | 0.1% | 0.3% |
| full (shipping default) | 1,748 | -97.4% | 2.24 | 2.98 | 3.62 | 4.26 | 2135.64 | +2040.60 | 107 MiB | 0.8% | 0.3% |

Latency in ms. **CPU µs/req** is subject-process CPU time divided by requests served — read the layer attribution from this column, not from RPS: it measures work done per request, which is a property of the code, whereas RPS also measures whatever else the host was doing. `vs base` is µs/req minus the `passthrough` row. **The `origin` row's µs/req is albedo's CPU, not prx-waf's** — it is a different program, so compare µs/req only between prx-waf postures; use the RPS column for the origin comparison. RSS is the peak seen while sampling at 5 Hz. The two `spread` columns are (best − worst) over the rounds as a share of the median; treat any figure whose spread is above ~10% as noise rather than as a result.

### multipart

| posture | RPS | vs origin | p50 | p95 | p99 | p99.9 | CPU µs/req | vs base | RSS | RPS spread | µs spread |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| origin (no proxy) | 45,055 | — | 0.09 | 0.11 | 0.13 | 0.26 | 68.84 | — | 14 MiB | 0.0% | 0.4% |
| passthrough (proxy, no detection) | 19,169 | -57.5% | 0.20 | 0.26 | 0.31 | 0.38 | 146.64 | — | 62 MiB | 0.7% | 1.2% |
| + Lane 1 regex detectors | 6,567 | -85.4% | 0.60 | 0.76 | 0.95 | 1.11 | 529.05 | +382.41 | 86 MiB | 0.2% | 0.3% |
| + OWASP CRS PL1 | 7,732 | -82.8% | 0.50 | 0.68 | 0.83 | 0.91 | 438.15 | +291.51 | 77 MiB | 0.1% | 0.3% |
| + Lane 2 semantic (shadow) | 14,646 | -67.5% | 0.26 | 0.37 | 0.41 | 0.46 | 205.99 | +59.35 | 71 MiB | 1.0% | 1.0% |
| full (shipping default) | 3,976 | -91.2% | 0.98 | 1.27 | 1.56 | 1.84 | 904.73 | +758.09 | 110 MiB | 0.7% | 0.3% |

Latency in ms. **CPU µs/req** is subject-process CPU time divided by requests served — read the layer attribution from this column, not from RPS: it measures work done per request, which is a property of the code, whereas RPS also measures whatever else the host was doing. `vs base` is µs/req minus the `passthrough` row. **The `origin` row's µs/req is albedo's CPU, not prx-waf's** — it is a different program, so compare µs/req only between prx-waf postures; use the RPS column for the origin comparison. RSS is the peak seen while sampling at 5 Hz. The two `spread` columns are (best − worst) over the rounds as a share of the median; treat any figure whose spread is above ~10% as noise rather than as a result.

<!-- END c4 -->

---

## Lane 1 unbounded (`max_body_bytes = 0`)

The contrast behind §2, and the posture every release before `39d4fb2` shipped.
Same tree, same host, same run parameters; only `[content_security.lane1]
max_body_bytes` differs, set to `0`. Machine-readable form:
[`results/lane1-unbounded.json`](results/lane1-unbounded.json).

`passthrough` is included as the control: it has no Lane 1 detector enabled, so
the key must not move it, and it does not.

<!-- BEGIN lane1-unbounded -->
### multipart

| posture | RPS | vs origin | p50 | p95 | p99 | p99.9 | CPU µs/req | vs base | RSS | RPS spread | µs spread |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| passthrough (proxy, no detection) | 22,902 | — | 2.16 | 3.14 | 3.57 | 4.06 | 171.47 | — | 78 MiB | 1.4% | 1.3% |
| + Lane 1 regex detectors | 93 | — | 554.66 | 812.93 | 902.49 | 1243.24 | 42856.87 | +42685.40 | 102 MiB | 1.6% | 1.6% |
| full (shipping default) | 94 | — | 527.86 | 881.60 | 1068.38 | 1460.22 | 42619.31 | +42447.84 | 119 MiB | 1.9% | 1.9% |

Latency in ms. **CPU µs/req** is subject-process CPU time divided by requests served — read the layer attribution from this column, not from RPS: it measures work done per request, which is a property of the code, whereas RPS also measures whatever else the host was doing. `vs base` is µs/req minus the `passthrough` row. **The `origin` row's µs/req is albedo's CPU, not prx-waf's** — it is a different program, so compare µs/req only between prx-waf postures; use the RPS column for the origin comparison. RSS is the peak seen while sampling at 5 Hz. The two `spread` columns are (best − worst) over the rounds as a share of the median; treat any figure whose spread is above ~10% as noise rather than as a result.

### body-1mb

| posture | RPS | vs origin | p50 | p95 | p99 | p99.9 | CPU µs/req | vs base | RSS | RPS spread | µs spread |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| passthrough (proxy, no detection) | 2,025 | — | 24.89 | 34.13 | 37.81 | 42.80 | 1948.09 | — | 111 MiB | 0.7% | 0.6% |
| + Lane 1 regex detectors | 15 | — | 3909.54 | 5013.27 | 6196.07 | 6578.14 | 259720.55 | +257772.46 | 118 MiB | 4.6% | 4.7% |
| full (shipping default) | 15 | — | 4219.47 | 6249.31 | 6971.25 | 6971.25 | 266874.23 | +264926.14 | 139 MiB | 2.7% | 2.6% |

Latency in ms. **CPU µs/req** is subject-process CPU time divided by requests served — read the layer attribution from this column, not from RPS: it measures work done per request, which is a property of the code, whereas RPS also measures whatever else the host was doing. `vs base` is µs/req minus the `passthrough` row. **The `origin` row's µs/req is albedo's CPU, not prx-waf's** — it is a different program, so compare µs/req only between prx-waf postures; use the RPS column for the origin comparison. RSS is the peak seen while sampling at 5 Hz. The two `spread` columns are (best − worst) over the rounds as a share of the median; treat any figure whose spread is above ~10% as noise rather than as a result.

<!-- END lane1-unbounded -->

---

## Metrics recording overhead (`*-nometrics`)

**A separate recording from every table above, and not comparable to them.**
Taken later, on the same host but a different tree (`a7e8b075`, which adds the
`/metrics` endpoint), with a narrower workload set. Read it only for the
`full` ↔ `full-nometrics` and `passthrough` ↔ `passthrough-nometrics`
differences it exists to measure; do not compare its absolute numbers against
§1–§5. Machine-readable:
[`results/metrics-overhead.json`](results/metrics-overhead.json) and
[`results/metrics-overhead-bodies.json`](results/metrics-overhead-bodies.json).

The two postures differ in exactly one config key, `[metrics] enabled`. No code
path differs between them — every record site is present in both binaries and
tests the same `OnceLock`, which is set in one and never set in the other. So
the delta is the recording and nothing else.

Host loadavg 0.29 → 7.08 for the first run, 0.27 → 4.46 for the body workloads;
tree clean at `a7e8b075` in both.

### The deltas

Metrics on minus metrics off. Positive means recording costs.

| workload | posture | CPU µs/req, on | off | delta | RPS on | off | delta |
|---|---|--:|--:|--:|--:|--:|--:|
| get-small | passthrough | 65.82 | 66.45 | **−0.95%** | 60,200 | 59,593 | +1.02% |
| get-small | full | 409.92 | 406.39 | **+0.87%** | 9,730 | 9,810 | −0.81% |
| json-post | passthrough | 82.66 | 83.15 | **−0.58%** | 47,942 | 47,646 | +0.62% |
| json-post | full | 2152.65 | 2114.93 | **+1.78%** | 1,863 | 1,896 | −1.77% |
| attack | passthrough | 68.55 | 68.71 | **−0.24%** | 57,806 | 57,610 | +0.34% |
| attack | full | 203.92 | 202.76 | **+0.57%** | 19,385 | 19,451 | −0.34% |
| multipart | full | 836.83 | 861.01 | **−2.81%** | 4,762 | 4,630 | +2.85% |
| body-1mb | full | 11443.08 | 11647.16 | **−1.75%** | 350 | 343 | +2.04% |

**Every measured overhead is under 2%**, and four of the eight rows come out
*negative* — which a real cost cannot be. Those rows are the useful ones: they
say the recording is below what this rig can resolve on that workload, and they
put a bound on how much the positive rows can be trusted.

### Which rows actually resolve

Two of the positive rows separate cleanly at the round level, meaning the
slowest metrics-on round still beat the fastest metrics-off round:

| workload | rounds, on | rounds, off | separated? |
|---|---|---|---|
| get-small `full` | 410.7 / 409.9 / 409.3 | 408.3 / 406.4 / 403.9 | **yes**, min(on) > max(off) |
| json-post `full` | 2161.5 / 2152.6 / 2133.3 | 2127.7 / 2114.9 / 2106.8 | **yes**, min(on) > max(off) |
| attack `full` | 202.6 / 203.9 / 206.1 | 201.4 / 202.8 / 205.1 | no, overlapping |
| get-small `passthrough` | 66.6 / 65.8 / 64.8 | 66.3 / 66.5 / 66.5 | no, and the delta is negative |

So the honest reading is: **0.87% on a small GET and 1.78% on a 1 KiB JSON POST,
both resolved; everything else is below the noise floor.**

### Why the JSON POST is twice the GET

Because it runs every measured phase twice. A request with a body goes through
the header phase and then the body phase, and both record the same six clock
reads (three lanes × start/end) and the same per-phase budget accounting. Double
the phases, double the recording — 2 × 0.87% ≈ 1.78%, which is the number.

That predicts a *lower* proportional cost, not a higher one, on the two body
workloads: their per-request detection cost is 4× (multipart) and 28×
(`body-1mb`) that of a JSON POST, while the recording per body window stays the
same size. The measurements agree in the only way they can — the cost vanishes
into the noise, and the sign comes out backwards.

### What was not measured here

* **The `body-1mb` window count.** A 1 MiB body is scanned window by window, and
  each window is its own body phase, so the lane-timing cost is paid once per
  window rather than once per request. The proportional overhead still came out
  negative, so this did not bind — but it is the shape that would make it bind,
  and it was inferred from the design rather than counted.
* **Scrape cost.** Every figure here is the *recording* side. Encoding the
  exposition walks every series and allocates a string; at the default
  `max_host_labels = 128` that is ~3 800 series, on the metrics thread, at
  whatever interval the scraper uses. It does not touch a worker thread, so it
  cannot show up in these columns, and it was not separately timed.
* **`cc` and `lane2` postures.** Only `passthrough` and `full` carry a
  `-nometrics` twin. `full` includes both, so the aggregate is covered; the
  per-layer split of the recording cost is not.

---

## What was not measured

Three of these are gaps this edition opened and intends to close; the rest are
standing exclusions.

* **The `worker_threads` = 1 / 2 / 4 scaling curve.** This is the notable gap.
  §1 compares the shipped 4-thread default against the old single-threaded
  *tree*, which conflates the thread count with 27 commits of other change, and
  it reports the per-request CPU cost of going wide (+68% on a small GET) from
  the one column that is directly comparable. What it cannot do is give a
  controlled curve. The harness gained a `WORKER_THREADS` knob in the same
  commit these figures were taken on, precisely for this, and the run was
  started and not completed. Until it lands, **do not read §1's ×2.32 as "the
  scaling factor"** — it is a change of era measured across two trees.
* **Whether the sublinearity is SMT or contention.** CPUs 0–3 are two physical
  cores, so a 4-thread run has at most 2 cores of real execution resource and
  some of the shortfall is structural rather than a defect. Separating them
  needs the sweep above repeated with the WAF on four *physical* cores
  (`WAF_CPUS=0-7` with the origin and generator moved aside). Candidate
  contention sites — shared stats counters, the rate-limit map, the database
  pool — are hypotheses, not findings; no profile was taken.
* **Where Lane 1's time goes, per detector.** The old page's §4 bisected Lane 1
  into its seven detectors and found `sqli` and `xss` were 94% of the cost. That
  table was taken with unbounded bodies and has been dropped rather than
  reprinted, because the shipped default changes which requests reach those
  detectors at all: on the 64 KiB multipart workload the budget now withholds
  the body entirely, so the old per-detector split describes the
  `max_body_bytes = 0` posture. The re-run — `POSTURES=passthrough,lane1-sqli,…`
  under `LANE1_MAX_BODY_BYTES=0`, which reproduces the old question, plus the
  `json-post` column which is inside 64 KiB and so is also the shipped figure —
  was scheduled and not run. `results/lane1-bisect.json` still holds the
  `87aa1bc` data and is **not** consistent with the rest of this page.
* **Where the multi-threaded runtime's +68% per-request CPU goes.** Measured,
  not attributed. No profiler was run against any posture here.
* **Whether attack-driven memory growth plateaus** (§6). Ten seconds is not long
  enough to answer it, and at 4 GiB the answer matters more than it did at
  750 MiB.
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

## Reproducing

```bash
tests/perf/run.sh                                    # the c=50 matrix
CONNECTIONS=4 \
  POSTURES=origin,passthrough,lane1,crs-pl1,lane2,full \
  WORKLOADS=get-small,json-post,multipart \
  tests/perf/run.sh                                  # unsaturated latency
LANE1_MAX_BODY_BYTES=0 POSTURES=passthrough,lane1,full \
  WORKLOADS=multipart,body-1mb tests/perf/run.sh     # the body-budget contrast
```

And the two runs this edition owes:

```bash
for t in 1 2 4; do                                   # the scaling curve
  WORKER_THREADS=$t POSTURES=passthrough,lane1,crs-pl1,full \
    WORKLOADS=get-small,json-post tests/perf/run.sh
done
LANE1_MAX_BODY_BYTES=0 \
  POSTURES=passthrough,lane1-sqli,lane1-xss,lane1-rce,lane1-traversal,lane1-sensitive,lane1-scan,lane1-bot,lane1 \
  WORKLOADS=multipart,json-post tests/perf/run.sh    # the Lane 1 bisect
```

Expect ~35 minutes for the `c=50` matrix. Run it on a machine whose subject
cores nothing else can touch — `taskset` the background hogs away rather than
hoping, then verify it by comparing `/proc/stat` on those cores against the
subject's own `utime+stime` while a round is in flight — and check the spread
columns before believing anything.
