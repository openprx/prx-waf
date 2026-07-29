# Logs and metrics: the same events, said the same way

An incident is worked in two moves. The dashboard says *something changed* —
`prxwaf_requests_total{action="block"}` stepped up on one host. The log says
*which requests* — the client, the path, the rule. The second move only works if
both sides call the same thing by the same name, count it on the same boundary
and bucket it into the same categories. Where they diverge, the pivot silently
fails: the operator greps for a word the log never writes, or reads a log line
that is not represented in any series, and concludes the wrong thing about a
live attack.

This document is the audit of that correspondence. It is written as a table of
concrete claims with `file:line` behind every one, because "the logs and metrics
agree" is not a statement anybody should take on trust.

**The three readers are not the same reader**, and this document does not try to
make them one:

| Surface | Written by | Read for | Bounded by |
|---|---|---|---|
| `/metrics` | `waf-common::metrics` | aggregate rates and trends | cardinality (`max_host_labels`) |
| the process log | `tracing`, plain `fmt` layer (`crates/prx-waf/src/main.rs:391`) | per-event forensics, startup posture, background-task health | log level and volume |
| `attack_logs` / `security_events` / the audit log | the engine's sinks | per-request evidence, retention-bounded | database retention, file rotation |

Alignment means the words and the boundaries match. It does not mean the log has
to carry everything a counter carries — see
[Deliberate asymmetries](#deliberate-asymmetries).

---

## 1. The verdict vocabulary

`RequestAction` (`crates/waf-common/src/metrics.rs:134-160`) exports four label
values — `allow`, `block`, `log_only`, `redirect`. `VerdictAction`
(`:165-185`) exports the three of those a detection can produce.
`WafAction` is stringified into the evidence tables with the **same four words**
(`crates/waf-engine/src/engine.rs:1236-1241` and `:1287-1292`), and the shadow
lane's own path spells it `"log_only"` (`:896`). So metrics and the *database*
already share one vocabulary.

The **process log** does not. Every row below is a request outcome that the
`logging` callback counts into `prxwaf_requests_total`
(`crates/gateway/src/proxy.rs:1052-1063`), against the tracing line the same
outcome writes.

| Outcome | metrics: series + label | log: file:line + what it says | aligned? |
|---|---|---|---|
| detection blocked, header phase | `requests_total{action="block"}` via `metric_action` at `proxy.rs:672`; `detections_total{phase,action="block"}` at `engine.rs:186` | `proxy.rs:678` `"WAF blocked request: ip=… path=… host=…"` | **word yes, field no** — "blocked" is prose inside the message; there is no `action=` token, and no `phase=` at all |
| detection blocked, body phase | same, `proxy.rs:817` | `proxy.rs:826` `"WAF blocked request (body): …"` | same |
| **redirect verdict** | `requests_total{action="redirect"}`, `detections_total{action="redirect"}` | `proxy.rs:688-693` — **no log line of any kind**; `proxy.rs:843-852` likewise | **NO** — the metric moves, the log is silent |
| **log_only verdict** | `requests_total{action="log_only"}`, `detections_total{action="log_only"}` | no tracing line anywhere; only `security_events.action = "log_only"` (`engine.rs:896`, `:1290`) | **partial, and deliberately so** — see §6 |
| **unrouted host → 404** | `requests_total{action="block"}` (`proxy.rs:608`) | `proxy.rs:603` `"No route found for host: …"` | **NO** — nothing in the line says this was counted as a block |
| **site administratively closed → 503** | `requests_total{action="block"}` (`proxy.rs:620`) | `proxy.rs:619` `"Site closed for host: …"` | **NO**, same |
| **duplicate `Host` → 400** | `requests_total{action="block"}` (`proxy.rs:544`) + `budget_events_total{subsystem="request_headers",limit="duplicate_host"}` (`:543`) | `proxy.rs:545` `"Rejecting request with duplicate Host headers: ip=…"` | **NO** — "rejecting", not "block" |
| **header fold over limit → 431** | `requests_total{action="block"}` (`proxy.rs:570`) + `{subsystem="request_headers", limit="values_per_name"\|"folded_bytes"}` (`:563-569`) | `proxy.rs:571` `"Rejecting request: header '…' exceeds the fold limits: ip=…"` | **NO**, and the log cannot distinguish the two limits the metric splits |
| **body over inspection ceiling → 413** | `requests_total{action="block"}` (`proxy.rs:756`) + `{subsystem="request_body",limit="inspect_ceiling_reject"}` (`:755`) | `proxy.rs:762` `"WAF rejected request body over the N byte inspection ceiling: …"` | **NO** — "rejected" |
| clean request forwarded | `requests_total{action="allow"}` — the default at `proxy.rs:1054` | `proxy.rs:1103` DEBUG `"Request completed: …"` | **partial** — DEBUG-only and carries no action word; acceptable, since an allow is the absence of a decision |

**The finding.** The word *block* appears in the log for exactly one of the
seven paths that increment `action="block"`. An operator who sees the block rate
step up and greps the log for `block` sees the detection blocks and misses every
routing, framing and budget refusal — which is precisely the population that
steps up when someone points a scanner at an unrouted vhost.

**Fixed by** giving all of these a structured `action = "block"` field, spelled
identically to the metric label, without touching the human-readable message. See
[§7](#7-what-changed).

---

## 2. The detection phase

`prxwaf_detections_total{phase}` uses `Phase::metric_label()`
(`crates/waf-common/src/types.rs:455-484`) — 26 snake_case values,
`sql_injection`, `xss`, `rce`, `owasp`, `crowdsec`, …

| Surface | Spelling | file:line |
|---|---|---|
| `prxwaf_detections_total{phase}` | `sql_injection` | `types.rs:455-484`, encoded at `metrics.rs` `encode_detections` |
| `attack_logs.phase` column | **`SQL Injection`** — `Display`, not `metric_label` | `engine.rs:1260` writes `result.phase.to_string()`; `types.rs:487-...` is the `Display` impl |
| `security_events` | **no phase column at all** — only `rule_id` / `rule_name` | `engine.rs:1294-1310` |
| tracing log | **no phase field anywhere** | — |

**The finding.** One enum, two spellings, on the two surfaces an operator pivots
between. `detections_total{phase="sql_injection"}` spikes; the corresponding
`attack_logs` rows say `SQL Injection`; the translation table between them exists
nowhere but in a reader's head. This is the sharpest mismatch in the audit.

**Not fixed here, on purpose.** `attack_logs.phase` is a persisted column with
rows already on disk in every deployment and a management API that returns it
verbatim. Rewriting the value written from today forward would leave a database
split between two spellings — strictly worse than one consistent wrong spelling,
because a query would then need *both*. This needs a migration that rewrites the
history alongside the code change, which is a separate, reversible piece of work.
It is recorded here as a known divergence with its resolution stated, and it is
listed in [§8](#8-known-gaps-not-closed-here).

---

## 3. The `host` dimension

| | metrics | log |
|---|---|---|
| Value | the `Host` header, interned into a bounded slot (`metrics.rs:906-943`), everything past `max_host_labels` folded to the literal `__other__` (`metrics.rs:850`) | the raw `Host` header, unbounded, interpolated into the message (`proxy.rs:678`, `:603`, `:619`) |
| Bound | `max_host_labels`, default 128, hard ceiling 4096 (`metrics.rs:90`, `:126`) | none |
| Where set | `proxy.rs:598` (HTTP/1.1), `http3.rs:600` (HTTP/3) — one shared table | every site formats its own |

**The pivot works in one direction only.** Log → metric is fine: the log names
the real host, and the operator can check whether that host has its own series by
scraping. Metric → log is where it breaks: given a step in
`requests_total{host="__other__",action="block"}`, **nothing tells you which real
hostnames are inside the fold.** The fold is unnamed by construction — that is
the whole point of the cardinality bound, and putting the folded names into a
label would undo it.

Worse, until now **the fold was completely silent**. `HostSlots::resolve`
(`metrics.rs:927-930`) hands back `HostSlot::OTHER` the moment `used >= max` and
says nothing; the startup broadcast states the configured cap
(`crates/prx-waf/src/main.rs:2736-2739`) but nothing ever reports that the cap
was *reached*. An operator whose 200-site node runs at the 128 default reads
`__other__` as a small tail forever, and every per-host dashboard they build is
quietly wrong for 72 sites.

**Fixed by** a one-shot WARN emitted at scrape time (not on the request path)
the first time the table is found saturated, naming the cap and the setting that
moves it. The naming of individual folded hosts stays out of both surfaces. See
[§7](#7-what-changed).

---

## 4. Budgets and degradation

`prxwaf_budget_events_total{subsystem,limit}` has 49 `(subsystem, limit)` pairs
(`metrics.rs:454-563`). Sorted by what the log does with each:

### 4.1 Logged at the site, aligned

| Metric labels | Log | file:line | aligned? |
|---|---|---|---|
| `upstream_timeout` / `connect`\|`read`\|`write` | `target: "waf.upstream_timeout"`, `"Upstream {stage} timeout …"` where `stage` is exactly `connect`/`read`/`write` | metric `proxy.rs:1086-1090`, log `proxy.rs:1091-1098` | **YES** — the only pair in the file where the metric's `limit` value and the log's word are the same token by construction |
| `request_body` / `inspect_ceiling_forward` | `"Request body exceeds the N byte inspection ceiling; remaining bytes are forwarded UNINSPECTED (PRXWAF_BODY_INSPECT_OVERFLOW=log)"` | `proxy.rs:782` / `:784-792` | words differ, meaning matches; the env var makes it findable |
| `request_body` / `inspect_ceiling_reject` | see §1 | `proxy.rs:755` / `:762` | see §1 |
| `request_headers` / `duplicate_host` | see §1 | `proxy.rs:543` / `:545` | see §1 |
| `request_headers` / `values_per_name` \| `folded_bytes` | one log line covers **both** metric values | `proxy.rs:563-569` / `:571` | **partial** — the metric splits what the log conflates |
| `http3_body` / `buffer_ceiling` | `"H3 request body exceeds N byte limit: …"` | `http3.rs:729` / `:733` | words differ, meaning matches |
| `response_cache` / `entry_bytes` | DEBUG `"skipping cache: entry exceeds the per-entry size cap"` on the `put` path only | metric `cache.rs:314` + `cache.rs:224`, log `cache.rs:308` | **partial** — `note_oversize_reject` (`cache.rs:223-226`) is the path the proxy actually takes for a streamed oversize body, and it has no log at all |

### 4.2 Aggregated into a periodic WARN

Seven of the eight `subsystem="queue"` counters report drops on a timer rather
than per drop, which is the correct shape: a drop storm must not become a log
storm.

Text below is **as it was before this pass**; §7.2 says what it is now.

| Metric labels | Periodic log text, before | file:line (before) | aligned? |
|---|---|---|---|
| `queue` / `attack_log` | `"attack_logs queue full — detections were BLOCKED but not recorded (back-pressure)"` | metric `detection_sink.rs:182`, log `:335-341` | **near** — the label is `attack_log`, the log said `attack_logs`; grepping the metric's token missed the line |
| `queue` / `security_event` | `"security_events queue full — …"` | `detection_sink.rs:193` / `:342-348` | **near**, same singular/plural drift |
| `queue` / `semantic_observations` | `"Semantic observation channel full — dropped observations (back-pressure)"` | `semantic_sink.rs:144` / `:264-269` | **NO** — "channel" not "queue", "Semantic observation" not `semantic_observations` |
| `queue` / `semantic_events` | `"Semantic shadow security-event channel full — dropped events (back-pressure)"` | `semantic_sink.rs:156` / `:271-276` | **NO**, same |
| `queue` / `audit_log` | `"Audit log channel full — dropped records (back-pressure)"` | `audit_log.rs:342` / `:494-499` | **NO**, same |
| `queue` / `notifications` | `"Notification queue full — events dropped (back-pressure); delivery is degraded"` | metric `waf-common/src/notify.rs:185`, log `waf-api/src/notify_runtime.rs:259-265` (reads `NotificationBus::take_dropped`) | **NO** — "Notification", not `notifications` |
| `queue` / `community_reporter` | `"Community signal channel full — dropped signals (back-pressure)"` | metric `community/reporter.rs:161`, log `:238-246` | **NO** — nothing in the line resembles `community_reporter` |
| `queue` / `cluster_peer` | — none | metric `waf-cluster/src/node.rs:324` | **NO** — counter only; the only queue with no periodic WARN at all |

**The finding.** `docs/metrics.md` tells operators to alert on
`prxwaf_budget_events_total{subsystem="queue", limit="attack_log"}`. When that
alert fires, the token in it does not appear in the log. Seven series, seven
different words for "queue".

**Fixed by** having every one of the seven read the token off
`BudgetEvent::limit()` into a `queue = …` field, and using that same token in
the message. Off the request path (a 30 s timer), so the cost is nil.

### 4.3 Counted, never logged — correctly

These fire per request, per field or per view. A log line on any of them is a
write-amplification surface an attacker controls directly, which is a lesson this
repository has already paid for. **They stay silent, and that is the right
answer.**

| Metric labels | Site |
|---|---|
| `crs_body_processor` / 9 limits | `checks/body_processors.rs:139,183,192,199,215,255,259,269,276,292` — no log statement exists anywhere in that file |
| `multipart` / 4 limits | `checks/multipart.rs:325,413,482,494` — no log statement in the file |
| `lane2_budget` / 9 limits | `checks/content_security/budget.rs:198,207,237,254,265,282,294,311,327` — no log statement in the file |
| `lane2_extract` / 2 limits | `checks/content_security/struct_extract.rs:143,472` — no log statement in the file |
| `lane2_detector` / `input_cap` | `checks/content_security/detectors.rs:1970,3088,3101,3109`, `xss_dom.rs:679` |
| `lane1_body` / `max_body_bytes` | `checks/mod.rs:410` |
| `crs_body_processor` / `form_args` | `waf-common/src/types.rs:135` |
| `response_body` / `inspect_ceiling` | `gateway/src/response.rs:500` — latched once per response, still per response |
| `response_cache` / `total_bytes` (eviction) | `gateway/src/cache.rs:185`, inside moka's eviction listener |
| `crowdsec` / `appsec_timeout`, `decision_cache_blind` | `engine.rs:627`, `engine.rs:1106` — per request during an outage, i.e. potentially *every* request |

### 4.4 Counted, never logged — and arguably shouldn't be silent

| Metric labels | Site | Why it stands out |
|---|---|---|
| `lane2_detector` / `parser_panic` | `detectors.rs:3058` | `metrics.rs:383-389` states outright that any non-zero value is "an upstream parser bug reachable from the network and worth an alert". It is the one budget event that is a *bug report*, not a tuning signal, and it is invisible to anyone without Prometheus. It is also replayable at rate, so a per-occurrence log is exactly the amplification trap — the answer is one line per process, not one per panic |
| `queue` / `cluster_peer` | `waf-cluster/src/node.rs:324` | the other seven queues all have a periodic drop WARN; this one has a counter and nothing else. The doc comment at `node.rs:313-316` says the drop "can contribute to a spurious election while leaving no trace at all — it now leaves a counter", which is true and is only half the sentence |

> **Correction.** A first pass of this audit listed `queue`/`notifications` and
> `queue`/`community_reporter` here as counter-only. They are not: both have
> periodic drop WARNs, at `waf-api/src/notify_runtime.rs:259-265` and
> `community/reporter.rs:238-246`. The first pass missed them by grepping for
> `.dropped()` while the notification path spells its accessor `take_dropped()`,
> and by reading only the lines around each `record_budget_event` call rather
> than the whole worker. Both are in §4.2 where they belong. The lesson is the
> obvious one: "no log for this" is a claim about the *absence* of code, and
> absence is the one thing a targeted grep is worst at proving.

### 4.5 `prxwaf_degraded_requests_total`

| | |
|---|---|
| metrics | one unlabelled counter, `engine.rs:739`, incremented once per verdict whose Lane 2 result carried `degraded` |
| log | **nothing** |

Coverage loss — "part of this request was never inspected" — has no log
representation at all. It is nonetheless left silent: `degraded` fires per
request phase on exactly the traffic shape an attacker chooses (large bodies,
deep JSON, many fields), so a per-occurrence log converts an inspection budget
into a disk-write budget. `budget_events_total` already says *which* bound was
responsible, and it is the series to alert on. Recorded as a deliberate
asymmetry rather than a gap.

---

## 5. Queue depth and upstream errors

| Concept | metrics | log | aligned? |
|---|---|---|---|
| items owed a write | `prxwaf_queue_depth{queue}`, 5 values (`metrics.rs:609-617`), inc/dec at `detection_sink.rs:185,196`, `semantic_sink.rs:147,159`, `audit_log.rs:345` | none — a gauge is a level, and a level has no event to log | **by design**; the drop counter (§4.2) is the event, and it is logged |
| pool occupancy | `prxwaf_db_pool{state}` sampled every 1 s (`waf-storage/src/db.rs:69-105`) | none | **by design**, same reason |
| upstream timeout | `budget_events_total{subsystem="upstream_timeout",limit=connect\|read\|write}` (`proxy.rs:1086`) | `target: "waf.upstream_timeout"` WARN naming the same stage word (`proxy.rs:1091`) | **YES** |
| upstream 502 (not a timeout) | `prxwaf_responses_total{status="5xx"}` only — `requests_total` still reads `action="allow"`, which is correct and documented (`docs/metrics.md`, "RED") | Pingora's own error path; the WAF adds no line | **partial** — the metric side is deliberate; the missing log is Pingora's to emit |
| HTTP/3 request smuggling | no metric | `target: "waf.smuggling"` WARN (`gateway/src/smuggling.rs:193`) | **inverted** — the only detection surface with a log and no counter. Shadow-only today; a counter would need a `Phase`, which is a detection-model change, not a logging one |

---

## 6. Deliberate asymmetries

Recorded so that a future reader does not "fix" them:

1. **`log_only` has no tracing line.** Lane 2 ships in shadow (`rollout_bps = 0`),
   so `log_only` is the *highest-volume* detection class on a node under attack.
   Its evidence lives in `security_events` with the identical action word
   (`engine.rs:896`) and in `semantic_observations`. A tracing line per shadow
   detection would be one log write per attack request, driven by the attacker.
2. **`prxwaf_degraded_requests_total` has no tracing line.** §4.5.
3. **The 30 Lane 2 / CRS / multipart budget events have no tracing line.** §4.3.
4. **`queue_depth` and `db_pool` have no tracing line.** They are levels; §5.
5. **The log keeps the real host; the metric folds it.** §3. The log must not
   lose the host — that is what makes forensics possible — and the metric must
   not gain it, because that is what makes the cardinality bounded. The two are
   correctly different, and the only defect was that the *existence* of the fold
   was unannounced.
6. **The log keeps free-form prose.** The alignment work adds structured fields
   next to the existing messages; it does not rewrite the messages into label
   soup. A log line is read by a person under time pressure.

---

## 7. What changed

Three changes, all off the per-request fast path.

### 7.1 One definition of the action word

`RequestAction::label()` (`metrics.rs:162`) is now `pub`, and
`RequestAction::of(&WafAction)` (`metrics.rs:180`) maps the engine's verdict
onto it. Every surface reads the word from there:

* the **metric** label, as before;
* the **evidence tables** — `engine.rs:1236` and `:1282` used to each carry
  their own four-arm `match` producing the same four strings, which is two
  copies too many; both now call `RequestAction::of(&decision.action).label()`;
* the **log**, at every HTTP/1.1 terminal refusal in `gateway/src/proxy.rs` —
  duplicate `Host` (`:550`), header fold (`:577`), unrouted host (`:610`),
  closed site (`:629`), detection block (`:698`), body-ceiling reject (`:800`),
  body-phase block (`:867`) — each of which now carries
  `action = RequestAction::Block.label()` alongside its existing message.

`metrics.rs`'s `the_action_word_has_exactly_one_definition` pins both halves.

The **redirect verdict got its first log line ever** (`proxy.rs:722` header
phase, `:889` body phase). It fires only when a configured rule resolves to
`redirect` — the same frequency class as a block, which has always logged — and
the destination it names is operator-configured, not request-controlled.

The two detection-block lines also gained `phase = <Phase::metric_label()>`,
which is the `prxwaf_detections_total{phase}` spelling and therefore joinable.
Deliberately *not* `Phase::to_string()`: that is the `attack_logs.phase` form
(§2), and a log carrying it would have been a third spelling of a word that
already has two.

**Cost.** Every added field is a `&'static str` from a `const fn` match — no
allocation, no formatting. Every site is a path that was already writing an HTTP
response and returning; a clean forwarded request reaches none of them, and the
`logging` callback is untouched.

### 7.2 One word for a queue

`BudgetEvent::limit()` (`metrics.rs:550`) is now `pub`, and all seven periodic
queue-drop WARNs read the `queue` field off it — `detection_sink.rs:342` and
`:351`, `semantic_sink.rs:267` and `:275`, `audit_log.rs:498`,
`community/reporter.rs:241`, `waf-api/src/notify_runtime.rs:263` — with the same
token repeated in the message text so a plain-text grep works as well as a
field query.

`every_queue_gauge_has_a_drop_counter_spelled_the_same` in `metrics.rs` also
pins the other half of the pair `docs/metrics.md` asks operators to graph
together: `prxwaf_queue_depth{queue}` and
`prxwaf_budget_events_total{subsystem="queue", limit}` are separate
enumerations that happen to agree, and nothing but that test stops one from
being renamed alone.

All seven fire from a 30 s timer in a background worker. None is on the request
path.

### 7.3 (pending)

---

## 8. Known gaps not closed here

| Gap | Why not |
|---|---|
| `attack_logs.phase` says `SQL Injection` where the metric says `sql_injection` (§2) | needs a data migration to rewrite existing rows; changing only new writes would split the column between two spellings, which is worse |
| HTTP/3's refusal log lines (`http3.rs:537,549,573,624,653,733`) did not get the `action` field its HTTP/1.1 twins did | `gateway/src/http3.rs` is being edited concurrently; the change is mechanical and should follow |
| `notifications`, `community_reporter` and `cluster_peer` drops have counters and no periodic WARN (§4.4) | each needs its own timer in its own worker; three separate small changes, none urgent — the counters exist and are alertable |
| `lane2_detector`/`parser_panic` has no log (§4.4) | wants the same one-shot-latch treatment as the host fold; deferred to keep this change reviewable |
| `waf.smuggling` has a log and no counter (§5) | a counter needs a `Phase` variant, which is a detection-model decision, not a logging one |
| The header-fold WARN cannot say which of `values_per_name` / `folded_bytes` fired (§4.1) | `fold_request_headers` records only the offending name; the metric re-derives the limit at `proxy.rs:564`, and threading it back out is a refactor of the fold's return type |
