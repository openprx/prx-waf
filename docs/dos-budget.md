# DoS budget

Every bounded resource in prx-waf, what its bound is, and — the part that
actually matters — **what happens when an attacker reaches it**.

This document is written for the person who has to put prx-waf in front of
production traffic and answer "which dimension can someone hurt us on". It is
not a tuning guide. A limit that rejects is a limit an attacker can use to deny
service to legitimate users; a limit that skips is a limit an attacker can use
to walk past detection. Both are listed, and which one a given limit is, is
stated for every entry.

Values are read from the source at the tree this document ships in. Where a
value is hardcoded, changing it requires a rebuild — that is called out,
because "just raise the limit" is not available to an operator for most of the
list below.

---

## How to read this

Every limit has an **exceed behaviour**, and there are only five in this
codebase. The whole document is easier once these are named:

| Behaviour | Meaning | Who it hurts |
|---|---|---|
| **reject** | the request is refused with a status code | availability — an attacker who can trip it denies service to that request only |
| **truncate** | the input is cut and inspection continues on the prefix | detection — an attacker hides payload past the cut |
| **skip** | the check does not run at all; the request proceeds uninspected by *that* check | detection — strictly worse than truncate, because zero bytes are examined |
| **degrade** | like skip, but the miss is recorded on the verdict (`degraded`) | detection, but observably |
| **drop+count** | a background record is discarded and a counter is incremented | observability — the request itself is unaffected |

Two things follow that are worth internalising before the tables:

* **Only three limits in the entire request path reject.** Everything else is
  truncate, skip or degrade. prx-waf is overwhelmingly fail-open by
  construction: it prefers to deliver an uninspected request over dropping a
  legitimate one. That is a defensible product decision, but it means most of
  the limits below are **detection-bypass budgets, not availability budgets** —
  the number tells an attacker how much payload to put past the cut.
* **Two groups of limits are configurable from `configs/default.toml`**: the
  Lane 2 work budget (§2.1) and the Lane 1 body budget (§2.2). The second ships
  **disabled**, so out of the box only the first one binds. A third small group
  is env-var only. Everything else needs a recompile.

---

## 1. Request-path size and count limits

### 1.1 The three limits that reject

These are the only places a client can be refused for a resource reason.

| Limit | Value | Response | Where | Tunable |
|---|---|---|---|---|
| `MAX_HEADER_VALUES_PER_NAME` | 64 lines of one header name | **431** | `crates/gateway/src/context.rs:29` | no (rebuild) |
| `MAX_FOLDED_HEADER_BYTES` | 32 KiB folded per header name | **431** | `crates/gateway/src/context.rs:36` | no (rebuild) |
| `MAX_INSPECTED_BODY_BYTES` | 10 MiB request body | **413** | `crates/gateway/src/context.rs:149` | env `PRXWAF_BODY_INSPECT_MAX_BYTES` |
| `MAX_H3_REQUEST_BODY` | 10 MiB (HTTP/3 buffer) | **413** | `crates/gateway/src/http3.rs:41` | no (rebuild) |

The header limits reject rather than truncate deliberately: a truncated header
fold *is* a bypass, so refusing is the only safe answer
(`crates/gateway/src/context.rs:24-28`). Note the asymmetry — the **response**
side applies the same two constants but never refuses anything
(`crates/gateway/src/response.rs:323-331`); an oversized response header set is
simply delivered with the fold cut short.

The 10 MiB body ceiling is the one limit whose exceed behaviour an operator can
**invert**:

```
PRXWAF_BODY_INSPECT_OVERFLOW=reject   # default — 413, fail-closed
PRXWAF_BODY_INSPECT_OVERFLOW=log      # warn once, forward the rest UNINSPECTED
```

`log` is fail-open and exists for deployments that must accept bulk uploads.
If you set it, you have accepted that anything past 10 MiB is not scanned. The
switch emits one `warn!` per affected request
(`crates/gateway/src/proxy.rs:663-675`) and **no counter** — you cannot alert on
how often it fires.

`PRXWAF_BODY_INSPECT_MAX_BYTES=0` means *unlimited*, not *zero*
(`crates/gateway/src/context.rs:341`). The same is true of
`PRXWAF_RESPONSE_INSPECT_MAX_BYTES` (`crates/gateway/src/response.rs:465`).
Setting either to `0` removes the bound entirely. This is a foot-gun worth
knowing about before someone "disables" a limit by zeroing it.

### 1.2 Body inspection windows

| Constant | Value | Where |
|---|---|---|
| `BODY_PREVIEW_LIMIT` (request window) | 64 KiB | `crates/gateway/src/context.rs:136` |
| `BODY_WINDOW_OVERLAP` | 4 KiB | `crates/gateway/src/context.rs:143` |
| `MAX_INSPECTED_RESPONSE_BYTES` | 512 KiB | `crates/gateway/src/response.rs:85` |
| `RESPONSE_WINDOW_BYTES` | 64 KiB | `crates/gateway/src/response.rs:66` |
| `RESPONSE_WINDOW_OVERLAP` | 4 KiB | `crates/gateway/src/response.rs:73` |
| `RESPONSE_FLUSH_AFTER` | 100 ms | `crates/gateway/src/response.rs:95` |

The window is a **peak-memory bound, not a coverage bound**: the body is
scanned window by window up to the total ceiling, with 4 KiB of the previous
window replayed so a signature straddling a boundary is still matched. Peak
buffered bytes per in-flight request on the request path is therefore ~64 KiB,
not 10 MiB — which is what makes the 10 MiB ceiling affordable.

**Request bodies are withheld from the upstream until their window has been
scanned** (`crates/gateway/src/proxy.rs:632-640`). This is correct — nothing may
reach the origin unscanned — but it means request-body latency is additive, not
overlapped, and a large body pays scan time per window. This shows up directly
in the measured numbers for large-body workloads.

**The response ceiling is 512 KiB and is truncate, not reject.** Past 512 KiB
the remainder is delivered uninspected; the partial view is flagged to the rules
via `ResponseCtx::body_truncated` (`crates/gateway/src/response.rs:517-523`).
Rejecting is deliberately not offered on the response side.

### 1.3 Parsers

All hardcoded. All fail-open. None reject.

**multipart/form-data** — `crates/waf-engine/src/checks/multipart.rs`

| Limit | Value | Exceed behaviour |
|---|---|---|
| `MAX_BOUNDARY_LEN` (`:56`) | 70 bytes (RFC 2046) | envelope not parsed at all; zero parts, `malformed = true` |
| `MAX_PARTS` (`:66`) | 256 parts | first 256 kept, envelope marked malformed; remainder **falls back to whole-body inspection** |
| `MAX_PART_HEADER_BYTES` (`:74`) | 8 KiB per part | that single part is **dropped entirely** |
| `MAX_PART_HEADER_LINES` (`:81`) | 32 lines per part | that single part is **dropped entirely** |

Note the second-order effect: a part whose header block is oversized is dropped
*whole* — its `name`, `filename` and body never reach the detectors. An attacker
who can attach 33 header lines to a part removes that part from inspection.
The envelope is flagged `malformed`, which is the only signal that this
happened.

**Body processors** — `crates/waf-engine/src/checks/body_processors.rs`

| Limit | Value | Exceed behaviour |
|---|---|---|
| `MAX_BODY_BYTES` (`:48`) | 64 KiB | **processor skipped entirely** — no `ARGS_POST`, no `XML:` targets at all |
| `MAX_PARSE_INPUT_DEPTH` (`:43`) | 64 bracket levels | JSON parse declined outright (stack-overflow guard) |
| `MAX_JSON_DEPTH` (`:51`) | 32 levels | that subtree not descended; siblings continue |
| `MAX_JSON_ARGS` (`:58`) | 512 members | walk breaks, members found so far kept |
| `MAX_JSON_NODES` (`:63`) | 16 384 visits | walk breaks |
| `MAX_XML_EVENTS` (`:66`) | 20 000 events | reader stops, returns what it has |
| `MAX_XML_TEXT_BYTES` (`:69`) | 64 KiB | truncated on a char boundary, silently |
| `MAX_XML_ATTRS` (`:72`) | 512 attributes | remaining attributes of that element dropped |
| `MAX_FORM_ARGS` (`waf-common/src/types.rs:83`) | 256 urlencoded params | remainder folded into **one anonymous member** — values still seen by `ARGS` rules, names not seen by `ARGS_NAMES` rules |

**The 64 KiB `MAX_BODY_BYTES` is the most important number in this section.**
A JSON body of 64 KiB + 1 produces *no structured targets at all* — every
`ARGS_POST`-based CRS rule sees nothing. The raw-body surface is unaffected, so
rules reading `REQUEST_BODY` still fire; but structured-target coverage stops
dead at 64 KiB while the *body* ceiling is 10 MiB. The gap between those two
numbers (64 KiB vs 10 MiB) is the structured-inspection blind spot, and it is
not configurable.

XML entity expansion: there is no billion-laughs counter, and none is needed —
custom `<!ENTITY>` DTD definitions are never expanded, only predefined and
numeric character references are resolved
(`body_processors.rs:149-161`). Amplification is structurally impossible rather
than counted.

**Lane 2 structured extractor** — `crates/waf-engine/src/checks/content_security/struct_extract.rs`

`MAX_EXTRACT_INPUT_BYTES` 64 KiB (`:99`, whole extraction skipped),
`MAX_STRUCT_DEPTH` 32 (`:85`), `MAX_GRAPHQL_RAW_OPENS` 256 (`:94`, GraphQL parse
declined, falls back to whole-body view), `MAX_MULTIPART_PARTS` 256 (`:103`,
Lane 2's own copy, independent of the Lane 1 constant), `MAX_VALUE_NODES` 256
(`:107`).

**Lane 2 detectors** — `crates/waf-engine/src/checks/content_security/detectors.rs`

`AST_MAX_INPUT_BYTES` 256 B (`:1836`), `MAX_AST_NESTING` 12 (`:1819`),
`SHELL_AST_MAX_INPUT_BYTES` 2 KiB (`:2263`), `SHELL_MAX_NESTING_DEPTH` 20
(`:2280`), `SHELL_WALK_MAX_DEPTH` 32 (`:2268`), `SHELL_MAX_WORD_PARSES` 32
(`:2286`), `XSS_MAX_INPUT_BYTES` 16 KiB (`xss_dom.rs:72`).

`SHELL_MAX_NESTING_DEPTH` is not a performance cap: exceeding it declines the
parse *before* `brush-parser` is called, because the lexer's stack overflow
would `abort()` the process — uncatchable, and therefore a remote crash. It is
a safety limit wearing a budget's clothes.

**Decode loops.** `MAX_DECODE_PASSES = 5` (`checks/mod.rs:189`) on the Lane 1
path: after five passes the value is inspected **with a residual encoded layer
still present**, an acknowledged bypass window
(`checks/mod.rs:183-188`). Lane 2 uses the tighter, configurable
`max_decode_rounds = 3`.

### 1.4 Header inspection coverage

`SCANNED_HEADERS` (`crates/waf-engine/src/checks/mod.rs:206-214`) is a
seven-name allowlist: `user-agent`, `referer`, `x-forwarded-for`, `x-real-ip`,
`x-original-url`, `x-forwarded-host`, `forwarded`. Every other request header is
never examined by the Lane 1 target collector. This is a permanent coverage
boundary, not a threshold that can be exceeded — worth knowing because it is
invisible in the metrics.

---

## 2. The configurable budgets

### 2.1 The Lane 2 work budget

`[content_security.budget]` in `configs/default.toml:464-475`, enforced in
`crates/waf-engine/src/checks/content_security/budget.rs`.

| Key | Default | Bounds |
|---|---|---|
| `max_fields_per_phase` | 64 | fields inspected per header/body phase |
| `max_views_per_field` | 12 | normalised views per field |
| `max_ast_attempts_per_request` | 6 | SQL AST parses |
| `max_ast_input_bytes_total` | 262 144 | total bytes handed to the AST parser |
| `max_html_parse_attempts_per_request` | 6 | HTML5 fragment parses |
| `max_html_parse_input_bytes_total` | 262 144 | total bytes handed to the HTML parser |
| `max_tokens_per_view` | 512 | tokens per view |
| `max_list_items` | 1 024 | list expansion |
| `max_preprocess_output_bytes_total` | 524 288 | **total normalised bytes per request** |
| `max_field_input_bytes` | 16 384 | per field, checked before any decode/alloc |
| `max_decode_rounds` | 3 | decode passes |

Exceed behaviour is **degrade**: the unit of work is skipped and
`SemanticVerdict::degraded` is set. Crucially, exhaustion does **not** retract
signals already found — the comment at `budget.rs:19-27` explains why: letting
exhaustion clear the verdict would hand an attacker a one-request kill switch.

`max_preprocess_output_bytes_total = 512 KiB` is the de-facto cap on Lane 2's
regex work per request. It is the primary Lane 2 knob if the WAF is CPU-bound —
but on a large body it is not the term that dominates; §2.2 is.

### 2.2 The Lane 1 body budget — present, and off by default

`[content_security.lane1] max_body_bytes` in `configs/default.toml:536-574`
(shipped **commented out**), compiled at
`crates/waf-engine/src/checks/content_security/config.rs:134` and enforced by
`Lane1BodyBudget::admits_body` (`crates/waf-engine/src/checks/mod.rs:321-330`),
which `request_targets` (`crates/waf-engine/src/checks/mod.rs:418`) consults at
`:462` before it builds the body-derived targets.

| Key | Default | Applies to | Exceed behaviour |
|---|---|---|---|
| `max_body_bytes` | **`0` = unlimited** | the four frozen Lane 1 detectors (`SQLi` / XSS / RCE / traversal) | **skip** — the body contributes no target at all, counted and logged |

**The default is a deliberate no-op.** `0` means unlimited, and a deployment
that never sets the key inspects exactly the bytes it always did; the only added
work on the request path is one integer comparison. Nothing below happens unless
an operator opts in.

**Why the knob exists.** Lane 1 is where the CPU goes. CPU µs/request over the
same binary with detection off ([`tests/perf/RESULTS.md`](../tests/perf/RESULTS.md)):

| layer | small GET | 1 KiB JSON | 64 KiB upload | 1 MiB body |
|---|--:|--:|--:|--:|
| Lane 1 | +83 | +616 | **+21,469** | **+102,228** |
| CRS PL1 | +88 | +487 | +199 | +4,667 |
| Lane 2 | +41 | +127 | +74 | +20 |

Lane 2 barely moves because §2.1 bounds it; CRS gets *cheaper* at 64 KiB because
`MAX_BODY_BYTES` skips its body processors past that point (§1.3). Lane 1 had
neither, and §5.3 means that cost is the throughput of the entire process:
**~9 rps of 1 MiB bodies per core, reachable by any unauthenticated client that
can POST.**

**Why one budget rather than one per detector.** All four detectors read the
body through the single `request_targets` collector
(`crates/waf-engine/src/checks/mod.rs:418`), and the measurements show they
share no work — the per-detector deltas sum to the aggregate within 1–7%, with
`sqli` +12,284 µs and `xss` +7,704 µs of Lane 1's 21,469 µs on a 64 KiB upload,
and `rce` +431 / `traversal` +437 making the four of them **99.6%** of it.
Capping the collector removes the cost from all four at once and keeps the
coverage statement binary: either Lane 1 read this body or it did not.
Per-detector control already exists separately, as the per-host
`defense_config.sqli` / `.xss` toggles.

**Skip, not truncate — and that is a real loss.** Past the budget, **zero** body
bytes are examined by those four detectors. A payload anywhere in an oversized
body — including its first byte — is invisible to Lane 1. Truncation would at
least catch prefix payloads, and it is not offered, for two reasons worth
stating rather than hiding:

* it cannot bound the work. The gateway hands the body over as a sequence of
  ≤68 KiB windows (§1.2), each in its own `RequestCtx`, so "scan the first N
  bytes" applied per window still costs N × window-count on a large body —
  the exact term the budget exists to delete. Bounding the *request* instead
  needs cumulative cross-window state, which Lane 1's frozen
  `Check::check(&RequestCtx)` signature cannot carry;
* **skip** is already what this codebase does at the same boundary — the CRS
  body processors (`body_processors.rs:130`, `:226`) — so there is one rule to
  learn, not two.

What still inspects an over-budget body: every CRS rule (its own 64 KiB
structured cap, unlimited raw-body scan), Lane 2 under §2.1, and the
`sensitive` detector. What still inspects the *request*: path, query string,
cookies and the seven scanned headers (§1.4) — the budget gates the body
targets only.

**The decision is O(1) and made twice.** `admits_body` compares the declared
`Content-Length` and this window's own length against the cap. Both terms are
needed: the `Content-Length` term makes the whole request decide the same way
for every window, so a 1 MiB body is skipped from its *first* window instead of
after 64 KiB have already been paid for; the window term covers chunked requests,
which declare no length (the gateway records `0`) and would otherwise walk past
the budget one window at a time. **Residual gap, stated rather than papered
over:** with a budget at or above the 68 KiB maximum window, a chunked body of
unknown length satisfies both terms and is scanned in full. Budgets below the
64 KiB window size are unaffected.

**It is never silent.** Every skip increments a process counter
(`lane1_body_skips()`) and, at most once per 30 s, emits a WARN naming the
budget, the observed size, the host and the path — the same drop-and-count
discipline as the queue sinks in §3, and with the same limitation: **log-only,
not exported as a metric.** Grep for `Lane 1 body budget exceeded`. Read the
counter as a rate signal, not a request count: it counts *detector invocations*,
so one oversized request contributes up to four per body window (four detectors,
each collecting its own targets). A non-zero budget also announces itself once
at startup (`Lane 1 body budget ACTIVE`), so "is this on?" is answerable from
the log rather than from the config file.

---

## 3. Queues and background sinks

No `unbounded_channel` exists anywhere in `crates/`. Every hot-path sink uses
`try_send` and **never applies backpressure to the request path** — a saturated
sink drops records rather than slowing traffic. That is the right trade, and it
means queue saturation is an *observability* incident, not an availability one.

| Sink | Capacity | Overflow | Counted? | Tunable |
|---|---|---|---|---|
| audit log (`audit_log.rs:74`) | 4 096 | drop | yes, `AuditLogSink::dropped()`, WARN every 30 s | no |
| semantic observations (`semantic_sink.rs:41`) | 4 096 | drop | yes | no |
| semantic events (`semantic_sink.rs:45`) | 4 096 | drop | yes | no |
| notification bus (`waf-common/src/notify.rs:37`) | 1 024 | drop | yes | **`notifications.queue_capacity`** |
| community reporter (`community/reporter.rs:122`) | `max(batch×16, 1024)` | drop | yes | `community.batch_size` |
| DB event broadcast (`waf-storage/src/db.rs:38`) | 1 024 | lag → silent loss | **no** | no |
| cluster peer channel (`waf-cluster/src/lib.rs:197`) | 256 | drop | **no, and not logged** | no |
| rules hot-reload (`rules/hot_reload.rs:33`) | **unbounded** (`std::sync::mpsc`) | — | — | debounced by `rules.reload_debounce_ms` = 500 |

Notes an operator needs:

* **All drop counters are log-only.** None of the four hot-path counters is
  exported as a metric. You can see saturation in the logs (a WARN every 30 s)
  and nowhere else, so you cannot alert on it. If audit completeness matters to
  you, this is the gap to close first. The Lane 1 body-skip counter (§2.2)
  follows the same pattern and has the same limitation.
* **Cluster broadcast drops are silent and uncounted**
  (`crates/waf-cluster/src/node.rs:314-320`). Heartbeats and election messages
  are broadcast through the same 256-slot channel, so a congested peer link is
  invisible *and* can contribute to spurious elections.
* The rules hot-reload channel is the only unbounded one. Its feed is local
  inotify events on the rules directory, not request traffic, so it is not
  attacker-reachable from the network — but a process with write access to
  `rules/` can grow it.
* **Cluster event batching awaits** (`waf-cluster/src/sync/events.rs:94`) and the
  admin API forward path awaits (`cluster_forward.rs:123-125`). These are real
  backpressure, but on background sync and the *admin* API — not the proxy data
  path.

---

## 4. Caches and per-IP state

### 4.1 Response cache

`crates/gateway/src/cache.rs:168-212`. Config: `cache.max_size_mb = 256`,
`default_ttl_secs = 60`, `max_ttl_secs = 3600`.

**The byte budget is enforced.** The moka cache is built with
`.max_capacity(max_size_mb × 1 MiB)` and a `weigher`, so each entry is charged
the memory it actually holds — body + headers + cache key + a fixed 256 B of
per-entry bookkeeping (`entry_weight`, `cache.rs:73-85`) — and moka evicts until
the total is inside the budget. The weight is computed once at insert and stored
on the entry, so the weigher on moka's bookkeeping path is a `u32` field read,
not a walk over the headers.

Worst case for the shipped default is therefore **~256 MiB** of cached response
bodies. Measured on a live node (real origin, `oha` driving distinct URLs,
`max_size_mb = 256`, RSS summed over the Pingora process tree):

| workload | before | after |
|---|---|---|
| 8 000 × 1 MiB distinct (8 GiB unique) | **4 510 MiB** RSS, 4 096 entries | **458 MiB** RSS, 255 entries |
| 60 000 req × 64 KiB over 100 k URLs | — | **321 MiB** RSS, 4 060 entries |

In both post-fix runs `bytes_used` settled just inside the budget — 267 533 760
and 268 406 600 bytes against `max_bytes` 268 435 456 — and never above it. The
RSS above the 256 MiB of cache is the ~56 MiB process baseline plus per-request
body buffers and allocator retention.

The pre-fix 4 096 entries is exactly `max_size_mb × 16`: proof the number was an
entry count. At 1 MiB per response that is 4 GiB of cache for a "256 MiB"
setting, on a node an operator sized for 256 MiB.

> **Changed in this version.** This used to be `.max_capacity(max_size_mb * 16)`
> — an **entry count**, no weigher, so every response counted as 1 regardless of
> size. With the same defaults that was 4 096 entries × the 8 MiB
> `CACHE_BODY_LIMIT` = **~32 GiB** against a nominal 256 MiB. If you had
> compensated by setting `max_size_mb` low, raise it: the number is now literal
> megabytes, and the old advice to treat it as "entries ÷ 16" no longer applies.

Two per-entry bounds apply, and both **refuse** an oversized response — it is
streamed through un-cached, never truncated and stored:

* `CACHE_BODY_LIMIT = 8 MiB` (`crates/gateway/src/context.rs:445`) — the
  per-request accumulation bound, independent of the cache budget.
* `max_size_mb / 16` (`MAX_ENTRY_FRACTION`, `cache.rs:59`) — no single entry may
  take more than 1/16 of the budget, so the cache always holds ≥16 entries and
  one large object cannot evict the entire working set. At the default that is
  16 MiB, i.e. *above* the 8 MiB body limit, so **at defaults this cap never
  binds** and hit rate is unchanged. It only starts refusing below
  `max_size_mb = 128`. Refusals are counted as `oversize_rejects`.

`GET /api/cache/stats` reports `bytes_used` against `max_bytes`, plus
`max_entry_bytes`, `evictions` and `oversize_rejects` — the byte figures are
settled (moka's pending write buffer is drained first), not approximate.

The cache key includes path, query and `Accept-Encoding`
(`cache.rs:240-252`), all attacker-controlled. Cache-busting query strings let
an unauthenticated client churn the whole entry set — bounded, so not a leak,
but a trivially triggerable cache-flush. The rails that do hold: only 2xx is
cached (`:277`), never with `Set-Cookie` (`:287-290`), and the request must
carry neither `Authorization` nor `Cookie` (`proxy.rs:177`).

### 4.2 CrowdSec decision cache — unbounded

`crates/waf-engine/src/crowdsec/cache.rs:37-39` — three plain `DashMap`/`Vec`
stores with **no entry cap and no LRU**. The only bound is TTL expiry, swept
every 5 minutes (`crowdsec/sync.rs:54`).

Keys come from the CrowdSec LAPI, not from request traffic, so this is not
attacker-controlled from the network — but it *is* unbounded, and a
misconfigured or compromised LAPI returning millions of decisions grows it
without limit.

Separately, `range_decisions` is a `Vec` scanned **linearly on every request**
under a read lock (`cache.rs:58-66`). A large CIDR decision set becomes a
per-request O(n) cost on the hot path. If you run CrowdSec with range
decisions, this is the term that grows with your decision count.

### 4.3 Per-IP rate-limit state

| Store | Cap | TTL | Key | Where |
|---|---|---|---|---|
| CC defense | 100 000 | 10 min | `(host_code, client_ip)` — **attacker-controlled** | `checks/cc.rs:11,14` |
| Admin API limiter | 50 000 | 10 min | client IP | `waf-api/src/security.rs:60,65` |
| Login limiter | 50 000 | 10 min | client IP | second instance, `crates/prx-waf/src/main.rs:2103` |
| Notification limiter | 4 096 | 24 h | admin-derived | `waf-api/src/notifications.rs:49,52` |

**The caps on the first three are enforced only by a once-per-minute background
task, not at insert.** Insertion is a bare `entry().or_insert_with(...)`
(`cc.rs:117`) with no length check, so between ticks an IP-rotating flood grows
the map past its nominal cap. With IPv6 the supply of unique keys is effectively
unlimited and the window is 60 seconds each cycle. The bound is an *average*,
not a *maximum*.

Worse, the eviction path is itself load-amplifying: `cc.rs:78-83` collects every
key into a `Vec` and sorts it — an O(n log n) full-map allocation, executed once
a minute, precisely when the map is at its largest. An attacker who inflates the
map is also choosing when the most expensive operation runs.

Only the notification limiter enforces its cap at insert
(`notifications.rs:76-81`), which is the shape the others should have.

---

## 5. Timeouts and concurrency

### 5.1 The proxy has no upstream timeout

`crates/gateway/src/proxy.rs:411` and `:424` construct `HttpPeer::new(...)` and
**never touch `peer.options`**. Pingora's `PeerOptions::default()` sets
`connection_timeout`, `total_connection_timeout`, `read_timeout`,
`write_timeout` and `idle_timeout` all to `None`
(`pingora-core-0.8.1/src/upstreams/peer.rs:474-478`), and `None` means *no
timeout*.

There is no config key for upstream timeouts anywhere in
`configs/default.toml` or `crates/waf-common/src/config.rs`.

Consequence: **a slow or black-holed upstream pins proxy connections
indefinitely, and there is no application-level bound an operator can set.**
This is the single largest availability gap in the list. It compounds with
§5.3.

The HTTP/3 path is the same shape:
`reqwest::Client::builder()` at `crates/gateway/src/http3.rs:176-178` sets
neither `.timeout()` nor `.connect_timeout()`, and reqwest's default is no
timeout.

### 5.2 Timeouts that do exist

| What | Value | On expiry | Tunable |
|---|---|---|---|
| CrowdSec AppSec (**on the request path**) | 500 ms | `Unavailable` → `appsec_failure_action`, default **allow** (fail-open) | `crowdsec.appsec_timeout_ms` |
| CrowdSec LAPI client (background) | 10 s | poll retried at the same cadence | no |
| CrowdSec mirror restore at startup | 10 s | start with empty cache (fail-open), logged | no |
| Backend health check | 5 s connect, 10 s poll | backend removed from pool; if the pool drains, falls through to the configured upstream | no |
| Response withhold flush | 100 ms | partial body released | env `PRXWAF_RESPONSE_INSPECT_FLUSH_MS` |
| Rule download | 30 s / 10 s connect | load fails, existing rules retained | no |
| IP feed fetch | 60 s / 10 s connect, 50 MiB cap | feed skipped this cycle | interval only |
| Notification webhook / SMTP | 10 s | delivery recorded failed | no |
| ACME order / download polls | 60 s deadline each | order abandoned, status written | no |
| Cluster election | 150–300 ms randomised | re-election | `cluster.election.*` |

**The AppSec timeout is the one to plan around**: it is awaited inline on every
request (`crates/waf-engine/src/engine.rs:430`). A wedged AppSec engine adds up
to 500 ms to *all* traffic, and with the default `allow` fallback the requests
are then let through unexamined. Set `appsec_timeout_ms` against your latency
budget, not against AppSec's typical response time.

### 5.3 Concurrency — the throughput ceiling

`crates/prx-waf/src/main.rs:1389` calls `Server::new(None)`, so Pingora falls
back to `ServerConf::default()`, which sets **`threads: 1`**
(`pingora-core-0.8.1/src/server/configuration/mod.rs:137`). The proxy service is
added with a bare `add_tcp` and no thread override
(`main.rs:1450-1452`).

**The proxy data path therefore runs on a single worker thread, on every
machine, and there is no configuration key to change it.** Adding cores does not
add proxy throughput. This is confirmed empirically in
[`tests/perf/RESULTS.md`](../tests/perf/RESULTS.md): under saturation the
process holds 13 OS threads but consumes **0.99 cores**, on a 16-core host.

There is likewise **no configurable connection-concurrency limit** for the proxy
listener, and no `quinn::TransportConfig` for HTTP/3 — no `max_idle_timeout`,
no `max_concurrent_bidi_streams`, no `receive_window`. HTTP/3 does set
`max_early_data_size = u32::MAX` (`crates/gateway/src/http3.rs:106`), which is
permissive 0-RTT and carries the usual replay surface.

Database pool: `storage.max_connections = 20`
(`configs/default.toml:10`).

### 5.4 Retry and backoff

* Cluster transport reconnect: exponential 500 ms → 30 s, resets on success
  (`waf-cluster/src/transport/client.rs:22,24,148-162`). **No jitter** — workers
  that lose the main simultaneously retry in lockstep.
* **CrowdSec LAPI poll has no backoff**: a down LAPI is retried every
  `update_frequency_secs` (default 10 s) forever
  (`crowdsec/sync.rs:53,197-200`), each attempt carrying a 10 s client timeout,
  so attempts can overlap.
* Community blocklist and IP feeds: fixed interval, no backoff. A community
  server returning perpetually mismatched versions makes every cycle a full
  re-pull, up to the 8 MiB response cap
  (`community/blocklist.rs:498-508`, `:23`).
* Upstream: **no retry logic at all**, so no amplification.

---

## 6. Dimensions with no bound

These are gaps, listed so nobody has to discover them during an incident. They
are recorded here as findings; none has been changed by this document.

1. **No upstream connect/read/write timeout** (§5.1). No config key exists.
   The most consequential entry on this list.
2. **HTTP/3 upstream client has no timeout at all** (§5.1).
3. **Proxy is single-threaded and not configurable** (§5.3). Throughput does not
   scale with cores.
4. **No proxy connection-concurrency limit**, and no QUIC transport config
   (§5.3).
5. **Response cache byte budget is not enforced** — nominal 256 MB, worst case
   ~32 GiB (§4.1).
6. **CrowdSec decision cache is unbounded**, with an O(n) linear CIDR scan per
   request (§4.2).
7. **Per-IP rate-limit maps are capped only once per minute**, and the
   enforcement is an O(n log n) full-map sort (§4.3).
8. **No regex compile-size, DFA-size or match timeout anywhere.** Every regex is
   built with a bare `Regex::new` — 15 call sites — so the `regex` crate's
   implicit 10 MB default applies and was never chosen. Operator-supplied custom
   rule patterns are compiled with no complexity or length cap
   (`crates/waf-engine/src/rules/engine.rs:393-395`). The `regex` crate is
   linear-time, so runtime is bounded by input size (§2), but compile-time
   memory is not bounded by anything deliberate.
9. **No cap on the total number of distinct header names.** The per-name limits
   in §1.1 are the only header bounds; `fold_request_headers`
   (`context.rs:73`) iterates every entry with no counter.
10. **No URI/path length limit and no 414 path.** No cap found in
    `crates/gateway/` or `crates/waf-engine/`.
11. **No query-string length or parameter-count cap at the gateway.** Bounded
    only downstream by `max_field_input_bytes` (16 KiB/field) and the folding
    `MAX_FORM_ARGS = 256`.
12. **No multipart part-payload, part-name or filename length caps** — bounded
    only transitively by the 64 KiB window the parser is handed.
13. ~~**`crowdsec.fallback_action` is documented and parsed but never read by
    the bouncer.**~~ **Fixed.** The bouncer check was a pure cache lookup whose
    `Option<DetectionResult>` could not distinguish "this IP is clean" from "I
    never got the ban list", so there was nothing for the setting to be applied
    to. It is now wired: the sync task publishes a degraded flag
    (`crates/waf-engine/src/crowdsec/health.rs`) that
    `CrowdSecChecker::fallback_for_miss`
    (`crates/waf-engine/src/crowdsec/checker.rs:57-71`) reads, and the engine
    applies `block` / `log` / `allow` at
    `crates/waf-engine/src/engine.rs:983-1010`. **Degraded means the cache is
    empty *and* LAPI could not be reached** — a pull that fails while decisions
    are still cached is stale, not blind, and deliberately does not trigger the
    fallback. The default is still `allow`, so nothing changes unless the
    setting is changed. `persist_decisions = true` remains the mitigation that
    keeps the cache populated in the first place, and is what keeps
    `fallback_action = "block"` from firing on every restart.
14. **`cluster.sync.events_queue_size` (default 10 000) is a dead knob** —
    declared at `crates/waf-common/src/config.rs:1499`, never read. The
    documented "drop oldest past this bound" behaviour does not exist.
15. **Queue drop counters are log-only, never exported as metrics** (§3).
16. **`SpentTokenRegistry` capacity is unverified** — no non-test caller of
    `SpentTokenRegistry::new` (`waf-cluster/src/crypto/token.rs:181`) was found,
    so its live capacity could not be established from source.

---

## 7. Operator checklist

If you are deploying prx-waf, the short version:

1. **Put a timeout in front of the upstream problem.** Until §6.1 is closed,
   the upstream must have its own liveness discipline — a load balancer with
   connect/read timeouts in front of the origin, or an origin that closes slow
   connections itself. prx-waf will wait forever otherwise.
2. **Size for one core of proxy throughput per process.** On a Ryzen 9 5900HX
   that is ~3,900 rps for a small GET, ~770 rps for a 1 KiB JSON POST and
   **47 rps for a 64 KiB upload**, in the shipping default configuration
   ([`tests/perf/RESULTS.md`](../tests/perf/RESULTS.md)). Horizontal scaling
   (more processes / more nodes) is the only lever. **Request-body size, not
   request rate, is what will exhaust you** — budget against your upload
   traffic, not your average RPS.
3. **`cache.max_size_mb` is literal megabytes** — set it to the memory you are
   willing to give cached responses and it will be respected (§4.1). It is no
   longer "entries ÷ 16"; if you had set it low to compensate for that, raise
   it. Watch `bytes_used` / `evictions` / `oversize_rejects` at
   `GET /api/cache/stats`. Or set `cache.enabled = false` if you have a CDN in
   front.
4. **Keep `persist_decisions = true`** — it is what stops a restart with a dead
   LAPI from serving with an empty decision cache. `crowdsec.fallback_action`
   now works too (`allow` by default), but treat `block` with care: it refuses
   *every* request whenever the cache is empty and LAPI is unreachable, which
   turns a CrowdSec outage into a site outage. `appsec_failure_action` is
   separate and also works.
5. **Decide the body-overflow posture deliberately.** The default (413) is
   fail-closed and correct for most deployments. `PRXWAF_BODY_INSPECT_OVERFLOW=log`
   is a decision to stop inspecting past 10 MiB.
6. **Know the 64 KiB structured-inspection boundary.** JSON/XML bodies past
   64 KiB produce no structured targets. If your API takes large JSON, the
   `ARGS_POST` rules are not protecting it. This boundary is visible in the
   performance data too: the CRS layer gets *cheaper* on a 64 KiB multipart body
   (+199 µs) than on a 1 KiB JSON one (+487 µs), precisely because it stopped
   inspecting.
7. **Decide the Lane 1 body budget deliberately — it ships off (§2.2).** Lane 1
   is where the time goes: on a 64 KiB upload the native regex detectors cost
   21 ms of CPU per request against Lane 2's 74 µs, and on a 1 MiB body 102 ms.
   `[content_security.lane1] max_body_bytes` bounds it, and the shipped default
   (`0` = unlimited) keeps the historical coverage *and* the historical DoS
   surface. Neither answer is free:
   * **leave it at 0** and body size, not request rate, is what exhausts you —
     ~9 rps of 1 MiB bodies per core (§5.3), attacker-chosen;
   * **set it** — just above the largest body your application legitimately
     posts — and anything larger is not scanned by `sqli` / `xss` / `rce` /
     `dir_traversal` at all. Not truncated: not scanned. CRS, Lane 2 and the
     non-body surfaces still inspect it, and every skip is counted and WARNed.

   The per-host `sqli` / `xss` toggles remain the blunter alternative (those two
   are 94% of Lane 1's cost) — they remove the detector from *all* traffic,
   where the budget removes it only from oversized bodies.
8. **Watch the logs for queue-drop WARNs**, since there is no metric. Grep for
   `channel full` and `dropped`.
9. **Expect memory to grow under attack.** Ten seconds of blocked traffic took
   the process from 110 MiB to 750 MiB in measurement, because every block
   writes to the database. Where that settles is not established — give the
   process a memory limit and alert on it.
