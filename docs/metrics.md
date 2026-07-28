# Metrics

What prx-waf exports on `/metrics`, what each series answers, and — the part
that decides whether you can run this in production — exactly how many series it
can produce.

The endpoint is **on by default** and bound to **`127.0.0.1:9127`**. It carries
no credential. Both of those are deliberate; see [Exposure](#exposure).

For how these series line up against the process log — which words match, which
events one surface carries and the other does not, and why — see
[`docs/logs-and-metrics.md`](logs-and-metrics.md).

---

## The endpoint

```
[metrics]
enabled = true
listen_addr = "127.0.0.1:9127"
max_host_labels = 128
```

| Key | Env override | Default |
|---|---|---|
| `enabled` | `PRXWAF_METRICS_ENABLED` | `true` |
| `listen_addr` | `PRXWAF_METRICS_LISTEN_ADDR` | `127.0.0.1:9127` |
| `max_host_labels` | `PRXWAF_METRICS_MAX_HOST_LABELS` | `128` (clamped at 4096) |

```
curl -s http://127.0.0.1:9127/metrics
```

**Why 9127 and not 9090.** 9090 is the port a Prometheus server itself listens
on, and the scraper this default is written for is a node-local Prometheus — so
a 9090 default collides on exactly the deployment it was meant to serve, and
whichever process starts second loses the bind. 9091 is pushgateway, so it is
out for the same reason. If your site standard is 9090 anyway, set `listen_addr`
explicitly; nothing else depends on the number.

A scrape config that works out of the box on a node-local agent:

```yaml
scrape_configs:
  - job_name: prx-waf
    static_configs:
      - targets: ['127.0.0.1:9127']
```

Startup logs one line stating the bind scope and the cardinality bound, so
"where is it and how big is it" is answerable from the log rather than from the
config file. A non-loopback bind logs it as a **warning**.

If the listener cannot bind — the usual cause being another process on the port
— the WAF logs one ERROR naming the address, the two settings that move the
listener and the fact that traffic filtering is unaffected, and **keeps
running**. Losing observability is bad; losing the firewall is worse. Recording
continues in memory, so the counters are correct the moment something can scrape
them again; only the scrape path is missing.

---

## Cardinality

This is the first thing to look at, not the last. A WAF's natural labels —
client IP, rule id, request path, user agent — are unbounded or effectively so,
and a label whose values an attacker chooses is a way to make the monitoring
system the outage instead of the thing that reports it.

**Every label except `host` is a compile-time enumeration.** There is no API in
`waf-common::metrics` that accepts a caller-supplied label string, so this is a
structural property and not a review convention.

**`host` is bounded by `max_host_labels`.** The first *N* distinct hostnames get
their own series; every one after that is folded into `host="__other__"`. The
series count is therefore a function of the setting, not of the traffic — a
client sending a million distinct `Host` headers produces `N + 1` label values,
which the test suite asserts directly.

### Worst case, exactly

| Metric | Label combinations | Series each | Total |
|---|--:|--:|--:|
| `prxwaf_requests_total` | `(H+1) × 4` actions | 1 | `4H + 4` |
| `prxwaf_responses_total` | `(H+1) × 5` classes | 1 | `5H + 5` |
| `prxwaf_request_duration_seconds` | `H+1` hosts | 19 (16 buckets + `+Inf` + sum + count) | `19H + 19` |
| `prxwaf_detections_total` | 26 phases × 3 actions | 1 | 78 |
| `prxwaf_degraded_requests_total` | — | 1 | 1 |
| `prxwaf_inspection_duration_seconds` | 3 lanes | 21 (18 buckets + `+Inf` + sum + count) | 63 |
| `prxwaf_budget_events_total` | 46 `(subsystem, limit)` pairs | 1 | 46 |
| `prxwaf_queue_depth` | 5 queues | 1 | 5 |
| `prxwaf_db_pool` | 2 states | 1 | 2 |

Total = **`28H + 223`**, where `H` = `max_host_labels`.

| `max_host_labels` | Series |
|--:|--:|
| 0 (fold everything) | 223 |
| 4 | 335 |
| 16 | 671 |
| **128 (default)** | **3 807** |
| 4096 (the clamp) | 114 911 |

The `4` row is measured, not calculated: a node configured with
`max_host_labels = 4`, driven with six distinct hostnames plus its own, scrapes
**exactly 335 series** — four host label values plus `__other__`, and the two
extra hostnames folded into it.

A **100-host deployment at the default** produces about **3 000 series** — the
order of magnitude of a single small exporter, and roughly what one `node_exporter`
emits. Nothing in that number moves with request rate, attack volume, distinct
client IPs, distinct paths or rule-set size.

The clamp at 4096 exists so a typo (`max_host_labels = 1000000`) fails as a
capped setting rather than as an allocation.

**Deliberately absent** (each of these was considered and refused):

| Label | Why not |
|---|---|
| `client_ip` | unbounded, attacker-chosen — the textbook way to kill a TSDB |
| `rule_id` | 291 CRS rules × host × action. Per-rule attribution lives in `security_events` and the audit log, which are queryable and bounded by retention |
| `path` / `url` | unbounded, attacker-chosen |
| `user_agent` | unbounded, attacker-chosen |
| `country` | ~250 values × host, and it answers a question the access logs answer |
| full status code | bounded, but ~60 codes × host to say what the class says |

---

## The metrics

### RED

```
prxwaf_requests_total{host, action}      action = allow | block | log_only | redirect
prxwaf_responses_total{host, status}     status = 1xx | 2xx | 3xx | 4xx | 5xx
prxwaf_request_duration_seconds{host}    histogram, 0.5 ms … 60 s
```

`requests` counts the WAF's **decision**; `responses` counts the status actually
written downstream. They differ in the two cases that matter: a `log_only`
detection is an allow that still detected something, and an upstream 502 is a
`allow` decision with a 5xx response. Both series are needed to tell those
apart.

Counted exactly once per request, from Pingora's `logging` callback, which runs
on every completion path including the ones where the WAF wrote the response
itself. A request decided in the header phase and again per body window
contributes one.

The duration histogram starts before host routing, so it covers ACME probes,
404s for unrouted hosts and refusals — not only the requests that reached an
upstream. `host="__other__"` therefore also collects requests refused before a
host was resolved at all (an over-long header fold, a duplicate `Host`).

**HTTP/3 is in these series too, on the same labels.** The QUIC forwarder does
not run under Pingora and has no `logging` callback, so it records from a
wrapper around its request handler — the one place all of its return paths pass
through — but everything downstream of that is shared: the same
decision-to-`action` mapping, the same `resolve_host` and therefore the same
`max_host_labels` bound, the same "status actually written" rule. An HTTP/3 404
for an unrouted authority is `action="block"` with a 4xx exactly as the
HTTP/1.1 one is, and a site reached over both protocols on the same port lands
on one series. HTTP/3 refusals that fire before an authority is settled on — a
duplicate `Host`, an over-long fold, an `:authority` its `Host` line
contradicts — join the `__other__` fold alongside their HTTP/1.1 equivalents.
`tests/e2e-http3-red-metrics.sh` reconciles a scrape against a real QUIC client
request by request.

**There is no `proto` label, and no HTTP/3-specific metric names.** A protocol
dimension would double the `28H` above — about 3 800 series at the default — to
answer a question the per-host SLO dashboards do not ask, and would halve the
sample count behind every per-host quantile. The protocol-specific failure
modes that do need separating have their own unlabelled counters:
`prxwaf_budget_events_total{subsystem="http3_body", limit="buffer_ceiling"}`,
and the `waf.upstream_timeout` log target, which the HTTP/3 forwarder shares
with the Pingora path. If you need per-protocol RED, run separate listeners in
separate processes rather than paying the cardinality on every deployment that
does not.

Block rate: `sum(rate(prxwaf_requests_total{action="block"}[5m])) / sum(rate(prxwaf_requests_total[5m]))`

### Detections

```
prxwaf_detections_total{phase, action}
```

26 phases (`sql_injection`, `xss`, `rce`, `owasp`, `crowdsec`, `nosql_injection`,
`ssti`, …) × 3 actions. This is the mix — what is being caught, by which layer,
and whether it is being blocked or only recorded.

Reading it against `prxwaf_requests_total` is the intended use: Lane 2 ships in
shadow (`rollout_bps = 0`), so its detections all appear as `log_only`, and the
ratio of Lane 2 `log_only` volume to Lane 1 `block` volume on the same traffic
is what a rollout decision is made from.

A whitelist hit is **not** counted. It short-circuits the pipeline but detects
nothing, and counting it would make the block-rate ratio meaningless.

### Layer cost

```
prxwaf_inspection_duration_seconds{lane}    lane = lane1 | crs | lane2
```

Histogram, 1 µs … 1 s. Bucket bounds are chosen for this workload, not the
library's defaults — those start at 5 ms, which would put every clean small
request in the first bucket.

The three chains share no work, and their cost ordering **inverts with body
size**: CRS is the cheapest layer on a 64 KiB upload, because its body
processors stop at 64 KiB, and the most expensive on a 1 MiB body, because its
raw-body scan does not. See [`tests/perf/RESULTS.md`](../tests/perf/RESULTS.md).
Deciding which layer to turn off needs the individual figure.

Observed **per request phase**, so a request with a body contributes two
observations to each active lane (header phase and body phase).

### Coverage loss

```
prxwaf_degraded_requests_total
prxwaf_budget_events_total{subsystem, limit}
```

`degraded` means part of a request was never inspected. `budget_events` says
which bound was responsible. One family with 46 `(subsystem, limit)` pairs
rather than 46 metric names, because the question is always the same shape.

The full mapping — every bounded resource, its exceed behaviour and its counter
— is in [`docs/dos-budget.md`](dos-budget.md), §8.

Three that are worth alerting on from day one:

| Series | Why |
|---|---|
| `{subsystem="lane1_body", limit="max_body_bytes"}` | bodies over 64 KiB are not scanned by `sqli`/`xss`/`rce`/`dir_traversal` **at all**. A steady rate means an application whose real traffic exceeds the budget |
| `{subsystem="crs_body_processor", limit="json_body_bytes"}` | JSON over 64 KiB produces no `ARGS_POST` targets, so the CRS rules that read them are not protecting that endpoint |
| `{subsystem="queue", limit="attack_log"}` and `{limit="security_event"}` | the WAF blocked a request and could not write the row proving it. Detection is unaffected; your evidence of it is not — this is the one drop an attacker benefits from |
| `{subsystem="queue", ...}` (the rest) | audit records, Lane 2 observations or notifications are being dropped |

### The write path behind the detection

```
prxwaf_queue_depth{queue}   queue = attack_log | security_event
                                  | semantic_observations | semantic_events
                                  | audit_log
prxwaf_db_pool{state}       state = connections | idle
```

Both are **gauges**, and they exist because the `subsystem="queue"` counters
above are trailing indicators: they fire only once a queue is already full, so a
queue that is filling — which is what memory growth under attack looks like from
the inside — produces no signal from them at all.

`queue_depth` counts **items handed to a background writer and not yet written**.
Every detection this WAF blocks costs two database rows, and those rows are
written off the request path; the depth is how far behind that write path has
fallen. `db_pool` says whether the pool is why:
`connections` pinned at `storage.max_connections` with `idle` at zero is
saturation, and a `queue_depth` rising against a saturated pool is the whole
diagnosis in two series.

The pair an operator should graph together is `prxwaf_queue_depth{queue="attack_log"}`
against `prxwaf_budget_events_total{subsystem="queue", limit="attack_log"}`: the
first is how much is waiting, the second is how much was given up on. Neither
number alone distinguishes "the WAF is not detecting anything" from "the WAF is
detecting and cannot write it down", and those two states must never look alike.

`db_pool` is sampled once a second by a background task rather than recorded at
a call site, because occupancy is a level and not an event. A scrape therefore
reads a value at most one second old.

---

## Cost

Recording is designed to be free enough not to need a decision. Every counter is
a slot in a flat `[AtomicU64]` indexed by its label enumeration, so an increment
is one relaxed `fetch_add` on a slot no other label combination shares — no
lock, no allocation, no shared cache line beyond the one slot. The `host` label
resolves to an integer once per request through a lock-free open-addressed table
and is then carried on the request context.

With `enabled = false` nothing is allocated and every record site is one acquire
load of a `OnceLock` and a predictable branch. The timing clocks are behind the
same gate, so a process with metrics off does not call `clock_gettime` at all.

Measured overhead is in [`tests/perf/RESULTS.md`](../tests/perf/RESULTS.md) under
the `*-nometrics` postures, which are byte-identical configurations with
recording off.

---

## Exposure

The endpoint is **unauthenticated**, and that is the smaller of two evils rather
than an oversight. Prometheus has no good way to carry a JWT; hanging `/metrics`
off the management API would push operators into configuring the **admin** token
— which can rewrite WAF rules, upload WASM plugins, mint cluster-join tokens and
replace TLS certificates — as a scrape credential, stored in the monitoring
system's config and copied into every relabel debugging session. An
unauthenticated socket on loopback has a strictly smaller blast radius than a
powerful credential in the wrong place.

**The bind address is the access control.** What a reader gets is per-host
request volume, block rate and detection counts by phase: a map of the sites
this WAF fronts, how busy each is, and which attacks against them are currently
landing. That is reconnaissance. Widen `listen_addr` only behind a firewall you
control — startup warns when you do, and names what leaks.

In Docker, the bind and the port publish are separate decisions. A loopback bind
inside the container plus `"0.0.0.0:9127:9127"` in the compose file is
network-wide exposure, and this process cannot see the second half.

If you do not want the endpoint at all, `enabled = false` removes the listener
and the recording. Startup will warn that the process is unobservable, because
it is.
