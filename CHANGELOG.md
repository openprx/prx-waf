# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Version numbers follow [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Fixed

- **`Dockerfile.release` no longer declares a `HEALTHCHECK` that no published
  image has ever had.** `HEALTHCHECK` is a Docker extension: the OCI image
  configuration reserves the `Healthcheck` key without defining it, buildkit
  exports OCI media types for every image result, and the field is dropped on
  the way out. `ghcr.io/openprx/prx-waf:v0.2.119` was built from a Dockerfile
  that declared one, and the config under its
  `application/vnd.oci.image.index.v1+json` holds no healthcheck anywhere.
  Podman is blunter about the same mechanism and prints "HEALTHCHECK is not
  supported for OCI image format and will be ignored" on every build.

  Keeping the instruction would mean exporting Docker media types, and buildkit
  refuses that for an annotated image — `cannot export annotations with
  "oci-mediatypes=false"` — so the trade is the annotated OCI index the
  release's metadata rides on against a field Kubernetes ignores in favour of
  its own probes. The instruction is gone and the reasoning is written where it
  stood.

  No deployment loses a check. `docker-compose.yml` and
  `docker-compose.firedrill.yml` each define one that curls `/health`; the
  image was rebuilt and brought up under compose to watch the container go
  `starting` → `healthy`. Bare `docker run` never had one, and the README and
  `docs/RELEASING.md` now say to pass `--health-cmd` for it.

### Added

- **The eighteen code-decided Lane 2 rules have prices.** `docs/lane2-rule-pricing.md`
  gains a section for them: fifteen priced by taking each away from the shipped
  posture, three by switching each on. Baseline shadow 139/10/2, enforce 75/2/2,
  reproduced in both directions.

  `xss.script_tag` is the most expensive rule in the inventory and the most
  valuable — **eight detections and two false positives**, at an identical score
  of 45 on both, so no threshold separates them. `xss.event_handler` carries four
  detections, a block and the third false positive. Taking both away is measured
  as its own run rather than summed: shadow 139 → **127**, false positives 10 →
  **7**, one block lost, blocking false positives unmoved. The five SQL-AST
  structures carry five of the corpus's seventy-five blocks and five detections
  on ten distinct rows, and two of the five carry blocks and no detection at
  all — the corroborating half of a two-detector family doing exactly what it is
  weighted to do.

  Of the three that shipped off behind a `#[cfg(test)]` constructor,
  `xss.object_embed` costs the eleventh false positive — a CMS page embedding a
  hosted PDF — for no detection. `xss.base_href` reads as free and is not: the
  corpus carries its shape, and `xss.script_tag` outranks it on the same field,
  so with the masking rule switched off it flags that row at 40.
  `xss.dangling_open_tag` scores one benign row under the line and nothing else.

  Two rules fire on nothing in either half: `xss.data_html_url`, because the one
  corpus row with a `data:text/html` payload delivers it in a query parameter
  rather than a URL attribute, and `deser.py_pickle_dangerous_global`, which has
  still never been observed firing. Both are recorded as no information rather
  than as clean.

- **The thirty-one default-off prices are reconciled with the post-`v0.2.188`
  baseline.** Those prices were taken before seven rules went default-on, so they
  carried a stale premise. The two baselines differ on **twelve attack rows and
  no benign row**, and the widened synthetic-view gate cannot reach further —
  only two corpus rows carry the pattern that widening added, in raw, percent-,
  base64- or hex-decoded form, and both are already among the twelve. Seven
  detector-disjoint group runs check the argument instead of trusting it: all
  thirty-one reproduce their recorded benign contact exactly, and only four touch
  any of the twelve rows, all cross-family and all far below the score the
  expected family already carries there.

  **One price moved.** `traversal.plain_dotdot` is `+1` detection for two false
  positives, not `+2`: `traversal.sensitive_abs_ops` now recovers `trav-005` in
  the baseline, so `trav-016` is the whole of what the rule buys. It is the only
  rule in the default-off set whose detections are outnumbered by its false
  positives. Nothing was switched.

- **The rules that decide in code are switchable.** `[content_security]
  rules_enabled` / `rules_disabled` reached 97 rule keys and refused 18 more that
  the engine emits: the five SQL-AST structures, the nine XSS DOM constructs, the
  two XSS JS token classes and the two pickle opcode grades. The inventory
  `prx-waf rules semantic` prints is now **115 keys, 81 on and 34 off**.

  The reason those keys were out of reach was that their detectors judge parsed
  structure rather than match a pattern, so there was no regex row to leave out of
  a compile step — a fact about how a rule is evaluated that had quietly become a
  fact about what an operator could configure. `docs/lane2-latent-pressure.md`
  priced that: three of the ten benign-corpus false positives come from
  `xss.script_tag` and `xss.event_handler` alone, and the only ways to silence
  either were the whole `xss` family or the whole lane.

  Switching a code-decided rule off leaves its detector running — still parsing,
  still feeding the XSS corroboration channel — and stops it naming that one
  construct, so the next-strongest enabled construct on the same input is still
  reported. `rules semantic` prints a DECIDES column (`table` / `code`, also
  `decided_by` in `--format json`) saying which kind a rule is.

  Three XSS DOM constructs that shipped default-off behind a `#[cfg(test)]`
  constructor — `xss.object_embed`, `xss.base_href`, `xss.dangling_open_tag` —
  are reachable from `rules_enabled` for the first time, so `tests/lane2/` can
  price them. `deser.py_pickle_dangerous_global`, which has never been observed
  firing, is in the inventory for the same reason.

  `ast.comment_obfusc` is deliberately **not** switchable and naming it is refused
  with that explanation: it is the label the AST detector puts on whichever
  structure it already matched when the view carried a comment marker, so it has
  no confidence of its own and disabling it has two irreconcilable readings.
  Disabling the structure reaches it.

  Default behaviour is unchanged to the byte. With both lists empty every
  detector reproduces its shipped construct set: lane 2 shadow 139/10/2, enforce
  75/2/2, `tests/ftw/` 1824/860/373.

### Changed

- **Seven Lane 2 rules now ship on.** `nosql.comparison_operator`,
  `nosql.regex_operator`, `nosql.logical_operator`, `nosql.expr_operator`,
  `deser.php_object_injection`, `traversal.sensitive_abs_ops` and
  `xxe.entity_expansion` had `default_on = false`; they now have `true`.

  `docs/lane2-rule-pricing.md` priced all thirty-eight default-off rules one at a
  time against the 390-row corpus. These seven recover eleven attacks between
  them and fire on **none** of the 220 benign rows — not "fired and stayed under
  a threshold", which the false-positive column cannot tell apart from silence,
  but never fired. They shipped off because "pending holdout calibration" was the
  only honest thing to say about a rule nobody could price, and leaving them off
  after the calibration would mean the measurement changed nothing for anyone who
  does not hand-edit a config.

  Shadow detection moves **128 → 139 of 170** (75.29% → 81.76%), and the eleven
  rows are the eleven the sweep named. `nosql_injection` goes 40.0% → 86.7%,
  `deserialization` 86.7% → 100%, `traversal` 90% → 95%, `xxe` 80% → 86.7%; the
  other six families do not move a row. `tests/lane2/baseline.json` is updated to
  the new shadow numbers.

  **Nothing about blocking changes.** Enforce mode is 75 blocked / 2 false
  positives / 2 blocking false positives before and after, byte for byte: every
  one of the seven carries a confidence between 45 and 75 against a
  `block_threshold` of 80, and none corroborates anything that was near the line.
  The lane still ships `log_only` with `rollout_bps = 0`. The benign columns do
  not move either — still 10 false positives, still 2 that would block, still the
  same named rows.

  One consequence the pricing sweep could not have measured: it enabled rules
  through `rules_enabled`, a runtime amendment, while `default_on` is compiled in
  and is read directly by the gate both synthetic-view emitters share. Flipping
  `traversal.sensitive_abs_ops` therefore also means a payload that *decodes* to
  `/etc/hosts` is now worth a blind base64/hex view. That is the gate's invariant
  working — it must never reject a structure a default-on detector accepts — and
  it is why the corpus was re-run against the flip instead of trusting the
  sweep's deltas. On this corpus the widening moved nothing.

  `traversal.sensitive_abs_ops` does now fire on a sentence that merely mentions
  `/etc/hosts` or `/proc/self`. No benign corpus row does, which is why it priced
  at zero, but "not in this corpus" is not "not in any traffic" — so that cost is
  written down as its own test rather than left implicit. Every one of the seven
  is switchable off by key: `rules_disabled = ["traversal.sensitive_abs_ops"]`.

  The rules that stay off stay off on evidence, not caution.
  `traversal.plain_dotdot` costs two false positives for one attack
  `traversal.sensitive_abs_ops` already catches. `ssti.jinja_arith_probe` scores
  `{{7*7}}` at 45 and scores a defensive security article *about* `{{7*7}}` at
  45 — the same number, so there is no threshold that separates them.
  `prx-waf rules semantic` now reports 66 rules running and 31 not.

### Added

- **Lane 2 rules can be switched on and off from config.** `[content_security]`
  takes `rules_enabled` and `rules_disabled`, two lists of rule keys that amend
  the state each detector rule ships in. Both are empty by default and the
  shipped detector sets are unchanged.

  Every Lane 2 rule carried a `default_on` flag that was a `bool` literal in a
  Rust table, read at construction, with the "compile everything" path reachable
  only from `#[cfg(test)]`. So a rule that shipped off could not be turned on
  without editing the engine and cutting a release — which meant
  `docs/lane2-blind-spots.md` could attribute fifteen of the forty blind corpus
  rows to rules that already exist and already clear their thresholds, and could
  not verify a single one of them. That number was arithmetic. The rules are
  default-off because nobody has priced their false positives, `tests/lane2/` is
  the instrument that would price them, and until now the experiment could not
  be set up.

  This ships the capability and none of the decisions: no rule changes state.

  A key that names no rule **stops startup**, quoting the key back and
  suggesting the near miss when there is exactly one. It is not warned about and
  not ignored, because a rule switch that silently does nothing is
  indistinguishable from one that works — the defect this repository already
  shipped as `start_status`, `max_list_items` and `listen_addr_tls`. The same
  key in both lists is refused too; there is no precedence rule because there is
  no obvious reading of that config.

  The switch is two-directional. Disabling a rule is a detection this WAF stops
  performing, so every disabled key is named in a startup `WARN` — but the
  alternative for an operator with one misfiring rule is turning off its family
  or the whole lane, which costs more detection than the rule was producing.
  `prx-waf rules disable` has offered the same thing for CRS rules for far
  longer.

- **`prx-waf rules semantic`** prints the Lane 2 rule inventory — key, family,
  detector, confidence, the state it ships in, and the state the loaded config
  gives it — with `--family`, `--state on|off|overridden` and `--format json`.
  It is the only way to read the vocabulary `rules_enabled` / `rules_disabled`
  accept, and it resolves the switches leniently so it still runs against the
  config whose typo just refused to start. (When this shipped it also stated what
  it did not cover — the AST SQLi detector and both XSS detectors decided in code
  and exposed no switchable rule. That gap is closed above; the command now prints
  a DECIDES column instead.)
- **The deserialization detector reads pickle opcodes.** The shipped
  `deser.py_pickle_global_exec` rule matches the *text* `GLOBAL` opcode,
  `c<module>\n<callable>`. `save_global` stops emitting that at protocol 4, and
  protocol 4 has been `pickle.DEFAULT_PROTOCOL` since Python 3.8: from there the
  module and the callable are two length-prefixed strings joined by a one-byte
  `STACK_GLOBAL`, with non-UTF-8 framing around them that reaches any text view
  as `U+FFFD`. So the rule caught an attacker who asked for an obsolete protocol
  and missed everything a bare `pickle.dumps()` has produced for seven years.
  That is not a tuning gap and no further regex closes it — the two names are
  never adjacent tokens in a text view.

  `deser.py_pickle_reduce_exec` (92) and `deser.py_pickle_dangerous_global` (85)
  come from an opcode walker instead. It reads the byte stream and nothing else:
  it constructs no object, imports no module, instantiates no class, and does
  not recurse — a pickle stream is flat, and a pickle nested inside another's
  `BINBYTES` payload is skipped as opaque bytes rather than re-entered. A
  module/callable pair is compared byte-wise against a closed table of execution
  primitives, and a hit reports the *table's* strings, so the detector cannot be
  made to echo the payload. Protocols 0 through 5 are covered and measured
  against byte-for-byte CPython output, including the `_compat_pickle` rewrite
  that turns `subprocess` into `commands` below protocol 3.

  Every argument length is validated against the remaining buffer before the
  read, input is capped at 4 KiB, and the simulated stack bound is set *equal* to
  that input bound so it cannot be reached — a smaller stack would have been a
  free evasion (pad with `NONE` until the walker gives up, then reduce). The
  parse is metered on `budget.max_ast_input_bytes_total`, so exhaustion marks
  `degraded` like any other parse. Base64 and hex wrappers are decoded by the
  walker itself: the preprocessor's blind gate requires the decoded bytes to be
  ≥ 85 % printable ASCII, which a binary pickle is not, and `lower_trunc`
  destroys the case a base64 token depends on.

  Measured on `tests/lane2/`: shadow detection **127 → 128** of 170
  (`deser-009`, a protocol-4 pickle base64-wrapped in a JSON field, goes from
  `blind` to detected), enforce blocking **74 → 75**, and the benign half is
  unchanged — the same **10** false positives and the same **2** blocking false
  positives, by name.

- **The TLS listener speaks HTTP/2.** ALPN now advertises `h2` ahead of
  `http/1.1`, so a browser negotiates HTTP/2 and a client that only speaks
  HTTP/1.1 is still served. Nothing else about the endpoint changes: the same
  routing, the same detectors, the same body inspection, and the same
  certificate.

  It could not be switched on before, because routing read the `Host` header
  and Pingora's h2 server does not write one — it delivers `:authority` in the
  request URI and passes the field map through untouched, so every compliant h2
  request would have routed on the empty string and got a 404. That is the same
  defect HTTP/3 shipped with, and it now has one fix rather than three:
  `gateway::authority::route_authority` decides which site a request addressed,
  for all three protocols. HTTP/1.1 is unaffected by construction — Pingora
  refuses the two request-target forms that carry an authority, so that path
  reads the `Host` field it always read.

- **A request whose authority contradicts its `Host` is refused with 400**, and
  counted as
  `prxwaf_budget_events_total{subsystem="request_headers",limit="contradicted_authority"}`.
  Reachable on h2, where a client may send both and neither `h2` nor Pingora
  compares them; not reachable on HTTP/1.1, whose request targets carry no
  authority. Picking a side would be the desync itself — this proxy would apply
  one site's policy to a request the origin resolves as another's — so the
  request is refused instead. Any non-zero value on that counter is an
  attempted request desync, not a tuning signal.

- **`upstream_ssl` splits "the site is TLS" from "the origin is TLS".** `ssl`
  was answering both questions with one bit. It is the flag ACME issues a
  certificate against — a statement about what clients speak to the site — and
  it was also, on HTTP/1.1 and HTTP/3 alike, the switch that decided whether
  this proxy dialled the origin over TLS. Those are independent in the
  commonest reverse proxy there is: public HTTPS in front, plaintext
  `127.0.0.1:8080` behind. Writing the only thing that expresses the first
  (`ssl = true`) silently asserted the second, and every request to that host
  returned `502 Bad Gateway` with nothing in the log tying the two together.

  `upstream_ssl = false` now gives a TLS site a cleartext origin, and
  `upstream_ssl = true` gives a plaintext site an encrypted one. Both data
  paths read it through one predicate, so they cannot drift apart on the
  question again.

- **`block_page_template` can now be set on a `[[hosts]]` entry.** The renderer
  has honoured a per-host block page since block pages existed, but only for
  hosts whose `hosts` row someone had edited by hand: the admin API does not
  surface the column and `HostEntry` had no field, so a config file that
  defined one served the built-in 403 page instead. It now reaches the runtime;
  the three placeholders (`{{req_id}}`, `{{rule_name}}`, `{{client_ip}}`) are
  substituted and HTML-escaped as before, and an entry without the key keeps
  the built-in template.

  The three other `HostConfig` fields a `[[hosts]]` block still cannot set —
  `remote_ip`, `remarks` and `exclude_url_log` — are left out on purpose and
  now say so in `configs/default.toml`. None has a reader in the request path:
  the upstream is dialled from `remote_host`/`remote_port`, `remarks` is a
  description for the admin UI's database-backed host list, and
  `exclude_url_log` is read by no code in any crate. Accepting them would
  reproduce the `start_status` failure — a key that parses and does nothing.

- **`[proxy.http2]` tunes the HTTP/2 frame-layer DoS ceilings.**
  `max_concurrent_streams`, `max_header_list_size_bytes`, and
  `max_pending_accept_reset_streams` were fixed at whatever Pingora's
  `default_h2_options` and the `h2` crate chose. The three now default to those
  same values — so leaving the table out changes nothing — but can be lowered
  to harden the listener, and setting them explicitly pins the Rapid-Reset
  (CVE-2023-44487) reset ceiling that `default_h2_options` otherwise left
  floating at whatever `h2` version is compiled in. Startup announces the
  effective limits; a wedging value (zero streams, zero resets, a sub-1-KiB
  header ceiling) is a hard startup error. The guards themselves are the `h2`
  crate's, which already answers Rapid Reset, the CONTINUATION flood
  (CVE-2024-27316), and the control-frame floods before a request reaches any
  detector — the evidence, and why no guard is duplicated here, is in
  `docs/http2-attack-surface.md`, with an end-to-end regression in
  `tests/e2e-h2-flood.sh`.

### Changed

- **A host relying on `ssl` to imply its upstream scheme is named at startup.**
  Leaving `upstream_ssl` unset still falls back to `ssl`, so no existing
  deployment changes behaviour — defaulting to plaintext instead would have
  silently downgraded an origin connection that really was encrypted, and a
  proxy that quietly stops encrypting is worse than a loud 502. The
  compatibility path is now a `WARN` per affected host instead, naming the host
  and the upstream it is about to dial over TLS. Setting `upstream_ssl` either
  way silences it.

### Removed

- **`[content_security.budget] max_list_items` is gone.** It never bounded
  anything: the key was parsed, validated non-zero and compiled into the
  per-request budget, and no code path read it. It is deleted rather than
  wired up, because the only limit it could plausibly have driven —
  the structured extractor's `MAX_VALUE_NODES = 256` — bounds nodes visited
  while walking a single GraphQL argument value, not list items, and adopting
  the key's 1 024 there would have quadrupled an attacker-reachable walk to make
  a name come true. A configuration file that still sets the key loads
  unchanged; the key is ignored, as it always was. Detection is unaffected —
  both the Lane 2 corpus and the go-ftw CRS baselines are unmoved.

- **The `rsa` crate is out of the dependency graph, and its advisory exemption
  with it.** RUSTSEC-2023-0071 (Marvin timing sidechannel, no fixed release)
  was the longest-argued entry in `deny.toml`: `rsa` arrived through
  jsonwebtoken's `rust_crypto` feature, which bundles it with the HMAC code
  this WAF actually uses and offers no way to take one without the other. The
  admin API now signs and verifies its JWTs through jsonwebtoken's `aws_lc_rs`
  backend instead, which drops `rsa` and twenty-one of its transitive
  dependencies. Nothing new is linked in for it: aws-lc-rs has been in the tree
  since the Pingora TLS backend was wired up.

  Tokens issued by an older build stay valid across the upgrade, and tokens
  issued by this build are accepted by an older one — both backends compute the
  same RFC 7515 HMAC-SHA256, and both directions were tested against a real
  process before the exemption was deleted. Operators need do nothing; no
  re-login, no secret rotation.

### Fixed

- **A fuzz crash reproducer now survives a job timeout.** The workflow step that
  uploads `fuzz/artifacts/` ran `if: failure()`, which is false while a job is
  being cancelled — so a soak that exceeded `timeout-minutes: 60`, or one killed
  by `cancel-in-progress`, threw away the crashing input. Those are the runs most
  likely to be holding one: a target that crashes late in a 1800-second soak, or
  one that wrote a `crash-*` file and then hung on the next input. The step now
  runs `always()`, and the retention rises from 30 days to 90 — a scheduled run
  reports to no pull request, and the 2026-07-27 soak crash sat unread for over a
  day before anyone looked.

- **`start_status = false` in the configuration file now closes the site.** It
  never did. `[[hosts]]` entries are deserialized into a struct that had no
  `start_status` field, and serde drops unknown keys without a word, so the key
  parsed cleanly and the host kept its default `true`: an operator who wrote
  `start_status = false` to take a site down got a successful startup and a site
  that carried on serving. The switch worked only through the admin API or a
  direct database row. A closed host answers `503 Service Unavailable` on both
  HTTP/1.1 and HTTP/3, as it always has when the flag came from the database.

- **`cat${IFS}/etc/passwd` now reads as a command execution rather than a path
  disclosure.** The semantic preprocessor's shell de-obfuscation always claimed
  to collapse `${IFS}` to a space, and its replacement step always did — but the
  fast-path guard in front of it tested for the substring `$IFS`, which `${IFS}`
  does not contain, so the braced spelling was declined at the door and no
  normalised view was ever produced. The braced form is the one attackers
  actually send (it needs no separator behind it), and it was reaching the
  detectors as an unadorned `/etc/passwd`: logged, but attributed to directory
  traversal instead of RCE, and invisible entirely when the target was
  `/proc/self/environ`, which no default-on traversal rule covers.

- **`{cat,/etc/passwd}` is now attributed to RCE.** A brace expansion on the
  command side is one word to a parser and two words to a shell, and the two
  words are the reader and the file it opens — no space appears in the request
  at all. The existing brace rule only covers the path side (`cat /etc/{passwd,
  shadow}`), so this form was logged as directory traversal. The new rule keeps
  the same bound as its sibling: a reader first, one flat closed group, the
  sensitive path within 64 bytes. Character-splitting spellings (`{c,a,t}`) are
  deliberately not covered — brace expansion yields separate words, so they run
  nothing.

---

## [0.2.119] — 2026-07-28

The first release since 0.2.31. Eighty-eight versions of work land together, so
the sections below are long; the four that decide whether this is deployable are
the metrics endpoint, the bounded write path, the graceful upgrade, and the
shell-parser guard.

### Added

- **`run --upgrade`: change the configuration or the binary without dropping
  connections.** A new process takes the listening sockets off the running one
  — the same kernel sockets, same accept queue — serves from them immediately,
  and the outgoing process finishes the requests it had already accepted and
  exits by itself. The port is never unlistened. Previously every change meant a
  restart, and a restart severed everything in flight.

  Pingora carried both halves of this all along; only the receiving half was
  ever armed. What had to be decided here was where the handover socket lives
  (Pingora's shipped default is `/tmp/pingora_upgrade.sock` and the socket is
  chmod `0666` at creation, so in a world-writable directory anyone local can
  intercept the handover and receive the WAF's listening descriptors — prx-waf
  derives a path in a `0700` directory it owns instead, and refuses one it does
  not), and what happens to the three listeners Pingora does not carry.

  Those three — admin API, metrics, HTTP/3 — are unavailable for the length of
  the overlap and come back on the new process; the data plane is unaffected
  throughout. HTTP/3 clients are dropped and reconnect, which QUIC makes
  unavoidable: its connection state lives in the process, not in the socket.
  Both processes hold a database pool during the overlap, so peak connections
  are twice `[storage] max_connections`.

  The order of the two commands matters and the reverse order is an outage.
  Procedure, failure modes, systemd and container notes:
  [`docs/graceful-upgrade.md`](docs/graceful-upgrade.md). New optional setting
  `[proxy] upgrade_sock` / `PRXWAF_UPGRADE_SOCK` moves the socket; unset, it is
  derived and announced at startup.

### Changed

- **Stopping now takes 30 seconds instead of 300.** `[proxy]
  drain_timeout_secs` (new, default 30, `PRXWAF_DRAIN_TIMEOUT_SECS`) is how
  long a process keeps serving already-accepted requests after `SIGTERM` or
  after handing its listeners to a replacement. Pingora's default, which
  prx-waf silently inherited, is 300 seconds — and it is an unconditional
  sleep, not a drain detector, so every stop cost the full five minutes whether
  or not anything was in flight. Under systemd that meant `systemctl stop` hung
  until `TimeoutStopSec` (90s by default) `SIGKILL`ed it, severing exactly the
  connections the wait was for; after a handover it meant five minutes of two
  processes, two database pools and no management API.

  Raise it if you proxy requests that legitimately run longer than 30 seconds,
  and keep it below your supervisor's kill timeout. Set it to 300 to keep the
  old behaviour. It is announced at startup either way.

- **`prxwaf_queue_depth` and `prxwaf_db_pool`: how far behind the write path
  is, before it starts dropping.** The `subsystem="queue"` budget counters are
  trailing indicators — they fire once a queue is already full, which is after
  the interesting part, and a queue that is filling but has not yet overflowed
  produces no signal from them at all. `prxwaf_queue_depth{queue}` is a gauge
  over the five background writers, counting items handed to a writer and not
  yet written; `prxwaf_db_pool{state}` publishes the `sqlx` pool's connection
  and idle counts, sampled once a second. Depth rising against a pool pinned at
  `storage.max_connections` with zero idle is the whole diagnosis in two series,
  and it is what turned §6 of `tests/perf/RESULTS.md` from an open question into
  a measured one. Seven more series, independent of `max_host_labels`.

- **`tests/perf/soak.sh`: a memory-shape harness.** `run.sh` reports the peak
  RSS from a ten-second window, which cannot distinguish a process that settles
  at a working set from one that rises until a queue bound stops it from one
  that rises for as long as traffic arrives — the three have the same first ten
  seconds and completely different operational meanings. `soak.sh` drives one
  posture for minutes and samples RSS, CPU, per-queue depth, pool occupancy, the
  drop counters and the rows that actually reached the database once a second;
  `soak_shape.py` fits the second half of the series and states the rule it used
  so the verdict is arithmetic rather than a shape somebody saw in a graph. It
  can freeze the database mid-run to exercise the overflow policy for real, and
  it stops itself at an RSS ceiling rather than OOM-ing the host.

- **Prometheus metrics on `/metrics`, on by default, bound to
  `127.0.0.1:9127`.** (Not 9090 — that is the port a Prometheus server itself
  listens on, and a node-local Prometheus is the scraper this default is written
  for, so 9090 would collide on exactly the deployment it serves.) The WAF
  previously exported nothing: request rate, block
  rate, detection mix, per-lane detection cost and every budget/degradation
  counter in `docs/dos-budget.md` were readable only by grepping logs, and
  several were not even logged. Seven metrics now cover RED by host and
  decision, detections by phase and action, per-lane inspection cost as a
  histogram, and one counter for every bounded resource that skips, truncates,
  degrades or drops. See [`docs/metrics.md`](docs/metrics.md) and
  `docs/dos-budget.md` §8 for the limit-to-counter mapping.

  **Cardinality is bounded by construction.** Every label except `host` is a
  compile-time enumeration — there is no API that accepts a caller-supplied
  label string — and `host` is capped by `[metrics] max_host_labels` (default
  128), folding into a single `__other__` series past the cap. Client IP, rule
  id, path and user agent are never labels. Total series is
  `28 × max_host_labels + 223`, about 3 800 at the default, and does not move
  with request rate, attack volume or rule-set size.

  The endpoint is **unauthenticated by design** and runs on its own listener
  rather than as a route on the management API: Prometheus has no good way to
  carry a JWT, and reusing the admin token would place a credential that can
  rewrite rules, upload plugins and replace certificates into the monitoring
  system's configuration. The bind address is the access control; a
  non-loopback bind logs a startup warning naming what a reader learns.

  A bind that fails is never fatal — losing observability is bad, losing the
  firewall is worse. It logs one ERROR naming the address, the stage that
  failed, the two settings that move the listener (`[metrics] listen_addr`,
  `PRXWAF_METRICS_LISTEN_ADDR`) and the fact that traffic filtering is
  unaffected, so the line is actionable without reading the source.

  Recording is lock-free — a flat `[AtomicU64]` indexed by the label
  enumeration, one relaxed `fetch_add` per event, with the `host` label resolved
  to an integer once per request through a lock-free interner. With
  `[metrics] enabled = false` nothing is allocated, every record site is one
  `OnceLock` load, and no timing clock is read.

  New dependency: `prometheus-client` (the Prometheus project's own Rust
  client), used only for its registry and text encoder. It adds `dtoa` and
  `itoa` and reuses the `parking_lot`, `syn`, `quote` and `proc-macro2` already
  in the graph.

- **Counters for limits that previously had none.** `docs/dos-budget.md`
  recorded four places as having no metric and, in one case, no log line at all;
  all are now exported: the fail-open body-overflow path
  (`PRXWAF_BODY_INSPECT_OVERFLOW=log`, which forwards everything past 10 MiB
  uninspected), the Lane 1 body-budget skip, all six background-queue drops
  including the cluster peer channel — which was neither counted nor logged,
  despite carrying heartbeats and election messages — and the CrowdSec
  `AppSec` timeout, the most consequential fail-open on the request path.

### Changed

- **rcgen 0.14 replaces the issuer certificate with an `Issuer` value, and the
  cluster CA no longer mints a throwaway certificate to sign node certs.**
  0.14 narrows `CertificateParams::signed_by` from `(key, &Certificate,
  &KeyPair)` to `(key, &Issuer<'_, _>)`, where `Issuer` holds exactly the three
  things signing actually reads: the issuer's distinguished name, its key
  identifier method, and its key usages. `CertificateAuthority::as_rcgen_issuer`
  previously had to self-sign a fresh CA certificate on every node-cert
  issuance purely to have a `Certificate` to hand to `signed_by`; it now returns
  `Issuer::new(params, key)` and that certificate is never built. The signed
  output is unchanged — the DN, key usages and signing key are the same values
  the discarded certificate carried, and the Authority Key Identifier still
  derives from the CA public key. The cluster mTLS integration tests
  (`two_node_heartbeat_exchange`, `mtls_rejects_unknown_cert`) exercise a real
  QUIC handshake against a chain built this way and still pass.

- **Two dependency majors with no call-site change: lz4_flex 0.14 and notify 8.**
  lz4_flex carries the cluster rule-sync snapshots (`sync/rules.rs`), where
  `checked_decompress` reads the four-byte little-endian uncompressed-size
  prefix by hand before letting the decompressor allocate. 0.12 through 0.14
  change nothing about that framing — `block::uncompressed_size` still decodes
  a `u32` from the leading four bytes — so the M-18 bomb bound keeps holding
  and a 0.11 node and a 0.14 node still understand each other's snapshots. What
  the bump buys is upstream's own overflow work: 0.12 fixed integer overflows
  when decoding large payloads, 0.13 fixed `get_maximum_output_size` on 32-bit
  targets, and 0.13.1 fixed a panic in `From<io::Error> for frame::Error`.

  notify drives rules hot-reload (`rules/hot_reload.rs`), which uses only
  `RecommendedWatcher::new`, `watch`, and the three `EventKind` variants — all
  unchanged across 6, 7 and 8. The one default worth checking is symlink
  following, which 8.0 made configurable: `Config::default()` sets
  `follow_symlinks: true`, matching what 6 did unconditionally, so a rules
  directory reached through a symlink still reloads. On Linux the backend is
  `INotifyWatcher` either way; the 8.2.0 fixes are in that backend (report
  `max_user_watches` exhaustion, ignore events for unknown watch descriptors
  instead of reporting them as `Q_OVERFLOW`).

- **`[content_security.lane1] max_body_bytes` now defaults to `65536` instead of
  `0` (unlimited), and an over-budget body now degrades the verdict instead of
  being skipped silently.** Unbounded, the four Lane 1 regex detectors cost
  42.7 ms of CPU on a 64 KiB upload and 258 ms on a 1 MiB body — so a large
  POST, with no evasion and no authentication, was enough to take the process
  down at 93 and 15 requests per second respectively. 64 KiB is the boundary the
  CRS body processors already draw (`MAX_BODY_BYTES`), so both detection chains
  now stop reading a request body at the same size. Measured on a quiet host,
  one config default apart, the bound is worth **×75.5 on a 64 KiB upload and
  ×47.2 on a 1 MiB body** for the `lane1` posture (×45.1 and ×20.4 for the full
  shipping stack); the `passthrough` control does not move, as it should not.
  These supersede the provisional ×41 / ×37 recorded when the default landed,
  which were taken while a second benchmark shared the same cores and were kept
  out of `tests/perf/RESULTS.md` for that reason.

  **This reduces detection coverage.** `sqli` / `xss` / `rce` / `dir_traversal`
  see none of a body over 64 KiB — not a truncated prefix, none of it. If your
  application legitimately posts larger bodies, raise the key to just above
  them. `0` still means unlimited and now logs a startup WARN naming the DoS
  surface it reopens. Skips are counted, WARNed, and marked `degraded` on the
  semantic verdict so an uninspected request cannot be read downstream as an
  inspected one. See `docs/dos-budget.md` §2.2.

- **`rules/` now says which of its directories the engine loads, and the answer
  is one of seven.** `OWASPCheck::new()` reads `rules/owasp-crs/` from a
  hardcoded path and nothing else; the 275 rules under `advanced/`,
  `owasp-api/`, `modsecurity/`, `cve-patches/`, `bot-detection/` and `custom/`
  have never been evaluated by the running proxy. `rules/README.md` claimed
  the opposite ("loaded by the WAF engine at startup") and totalled the
  inventory at 558 rules, which is the number a reader would quote for
  coverage. The enforced number is 285.

  Every one of the 275 was audited against the real loader and against a
  benign-traffic corpus at the shipped defaults, and the finding is that most
  of them must **not** be loaded — not that the loader should be pointed at
  them. `rules/README.md` now carries the per-directory verdict with the
  measured numbers, and each directory's own README opens with it. Highlights,
  all reproduced against the engine rather than read off the YAML:

  - `advanced/` blocks 7 of 52 ordinary business requests. `ADV-SSRF-001`..`004`
    are `field: all` + `critical` + `paranoia: 1`, and `all` covers every
    request **header value**, so any request carrying a private address in
    `X-Forwarded-For` — i.e. every request behind a load balancer — is a 403.
    70 of its 77 rules block on their own.
  - `owasp-api/`'s `API-MASS-001/002/010` block `{"role":"admin"}`,
    `{"role":"system"}` and any body carrying `role` next to `is_admin`: every
    admin panel, every OpenAI-compatible request, every signup form that echoes
    the user object back.
  - 16 of `modsecurity/`'s 46 duplicate a CRS rule or a real subsystem
    (`cc.rs`, `ip_feed.rs`, `sensitive.rs`), and all 12 rules in its
    `data-leakage.yaml` are named "… in response" while reading `field: body`,
    which is the request.
  - `bot-detection/`'s `BOT-CRAWL-009` scores four crawlers that are on the
    engine's own good-bot allowlist, which does not protect them because
    `BotCheck` returning `None` does not short-circuit the pipeline.
  - Several rules across all six can never match, for reasons the schema
    documentation did not state: `field: headers` matches the name and the
    value separately (so a literal `Content-Range:` never appears),
    `field: cookies` yields values only, and `path`/`query`/`body` arrive
    already percent-decoded.

  `configs/default.toml` now states that `[rules]` is read by the CLI
  subcommands and not by the daemon, so an operator does not go looking for the
  switch that turns the other directories on. There isn't one.

  Pinned by `rule_directory_load_status_is_pinned` and
  `advanced_rules_block_ordinary_internal_load_balancer_traffic`. The shipped
  request path is untouched: `rules/owasp-crs/` is byte-identical, every Rust
  change is inside `#[cfg(test)]`, and the release binary rebuilds to the same
  SHA-256.

### Removed

- **`rules/geoip/country-blocklist.yaml`** — its two rules could never have
  loaded. `geo_iso` and `geo_isp` are not fields `Field::parse` knows, `in` is
  not an operator the loader implements, and the OWASP phase cannot reach
  `ctx.geo` at all. Country blocking goes through the custom-rules engine,
  whose `ConditionField` does have the geographic variants and which is
  reachable over `POST /api/custom-rules`; `rules/geoip/README.md` now says so
  instead of documenting five YAML fields that do not exist.
- **`rules/cve-patches/2024-xz-backdoor.yaml`** — CVE-2024-3094 is a pre-auth
  backdoor in `sshd`'s RSA path via `liblzma` and is not reachable over HTTP,
  so the file claimed coverage no HTTP WAF can provide. Its four rules matched,
  respectively, the string `n3t` anywhere in the request, any base64 run of 200+
  characters (every JWT), any URL containing `xz-utils` (every Debian mirror),
  and a `User-Agent` of `xz-exploit`. The same repository already says as much
  in `2024-recent.yaml`'s own comment on CVE-2024-6387.

### Fixed

- **HTTP/3 requests appear on `/metrics`.** The RED series were recorded from
  Pingora's `logging` callback, which the QUIC forwarder never reaches — it does
  not run under Pingora — so every HTTP/3 request was invisible except for one
  413 body counter. A node serving both protocols reported a request rate and a
  block rate that silently omitted one of them. The H3 handler now records from
  a wrapper that all of its return paths pass through, using the HTTP/1.1
  sources for every label: the same decision-to-`action` mapping, so a refusal
  is a `block` on both; the same `resolve_host`, so `max_host_labels` bounds
  HTTP/3 without a second cap and a site reached over both protocols on one port
  lands on one series; the same "status actually written" rule, so an upstream
  502 stays distinguishable from a WAF 403. Refusals that fire before an
  authority is settled on join the `__other__` fold, where their HTTP/1.1
  equivalents already are. No new label and no new metric name: a `proto`
  dimension would double the series count to answer a question the per-host
  dashboards do not ask. `tests/e2e-http3-red-metrics.sh` reconciles a scrape
  against a real QUIC client, outcome by outcome.

- **Sustained attack traffic no longer lets the attacker choose how much memory
  the process uses.** Every enforced detection wrote an `attack_logs` and/or a
  `security_events` row through one `tokio::spawn` per detection. Nothing
  connected the two sides: the request path spawned as fast as the proxy could
  block requests, the pool drained at `storage.max_connections`, and the
  difference accumulated in memory with no ceiling of any kind. Under a
  saturating SQLi flood from a single unauthenticated client this is 557,584
  rows in flight after thirty-one seconds and RSS on a straight line —
  **10.4 GiB per minute, R² 1.000** — which extrapolates to an OOM about three
  minutes in. `tests/perf/RESULTS.md` §6 measured the first ten seconds of that
  curve and said plainly that it could not tell whether it plateaued; §8 now
  answers it with a time series, and the answer was no.

  The two writers now share the bounded-channel discipline the audit log, the
  semantic sink and the community reporter already used: two 4,096-slot MPSC
  channels drained by one background worker, one synchronous `try_send` on the
  request path, no task allocation. Memory in front of the database is a
  constant of the configuration instead of a function of how long the attack has
  been running. The worker also composes one multi-row `INSERT` per drained
  batch rather than 256 round trips, which is what keeps the bound from
  mattering at real rates: measured over twenty minutes of the same flood,
  **RSS holds near 120 MiB and nothing is dropped at all** — every one of
  22,000 blocked requests a second is still recorded.

  **Overflow is loud, and it has to be.** A silently discarded security record
  makes "nothing was detected" and "something was detected and not written down"
  indistinguishable downstream. Two new budget counters,
  `prxwaf_budget_events_total{subsystem="queue", limit="attack_log"}` and
  `{limit="security_event"}`, count exactly the rows given up; the backlog
  before any of it is given up is on the new `prxwaf_queue_depth` gauge; and the
  worker WARNs a running total every thirty seconds. Freezing the database
  mid-flood reconciles exactly: 2,808,798 requests blocked, 1,863,291 rows
  written, 945,507 counted drops, no remainder — and RSS still flat at 114 MiB.

- **HTTP/3 routes on `:authority`, so HTTP/3 works at all.** The H3 listener
  resolved its route from `headers["host"]`, and HTTP/3 has no Host header —
  RFC 9114 §4.3.1 carries the authority in the `:authority` pseudo-header and
  tells a client that sends it to omit Host. `h3` folds `:authority` into the
  request URI and never writes a `host` field, so the lookup always came back
  empty, the router was handed `""`, and every HTTP/3 request answered 404
  whatever route it asked for. `curl --http3` and Chrome were both affected;
  the protocol was inert for anyone who enabled it. It ships disabled and needs
  a certificate to turn on, so a default install was never exposed.

  Routing is no stricter and no looser than before: an authority that matches
  no configured host is still refused with 404 and still reaches no upstream. A
  Host that contradicts `:authority` is now refused outright rather than
  resolved to either side. The routed authority is also what the origin is now
  told, so name-based vhosts behind an H3 route resolve the same site the WAF
  applied its policy to, and it is visible to the detectors as `host`, so a
  rule matching the Host header fires the same on either protocol.
  `tests/e2e-http3-authority.sh` covers both halves with a real QUIC client.

- **`action: log` is no longer silent.** The `Log` arm of `evaluate_rules`
  wrote one `debug!` line and produced no contribution, and the audit log is
  built from the contributions — so a matching `log` rule left no audit-log
  row, no `security_events` row, and at the default log level nothing at all.
  `rules/README.md` told rule authors to "start with `action: log`, monitor
  before blocking", which was an instruction to watch silence; 104 rules across
  the unloaded directories carry it. A `log` match is now recorded with
  `score 0`, which reaches the audit log and nothing else — no anomaly score,
  no verdict, no block. Without this the new `action_override = "log"` would
  have been the same trap wearing a new name.

  No shipped rule takes that branch (all 288 `rules/owasp-crs/` rules are
  `action: block`), so the go-ftw regression numbers are unchanged.

- **Request bodies are now routed by the same body-processor table upstream
  uses, instead of every body being handed to 154 rules that never asked for
  one.** The converter mapped `XML:/*` to the whole body unconditionally, so a
  JSON, plain-text or any-content-type body was scanned by every rule whose
  upstream target mentions XML. Of the 167 rules whose field carries `body`,
  **154 got it only from that mapping**; just 13 (920260, 921110, 931110 and
  the 944 family) really read `REQUEST_BODY` upstream.

  Narrowing `XML:/*` alone would have been a net loss, and finding that out is
  what this change turned on: upstream does not cover JSON through `XML:/*` at
  all. It covers it with a JSON body processor that flattens each leaf into
  `ARGS` — `modsecurity.conf` rule 200001, present in the very image the CRS
  regression suite scores against. So the fix is the whole table, not one
  entry: XML selects on rule 200000's content types and yields `XML:/*` as one
  concatenated text value plus `XML://@*` per attribute (matching
  `xmlNodeGetContent`, which excludes element names); JSON flattens to `ARGS`
  with v2's dotted paths; multipart contributes its non-file parts, as it
  already did.

  go-ftw, CRS v4.25.0, 4674 tests. Log mode — the rule-id-accurate measure —
  **2779 → 2782 / 3742 → 3746 / 4222 → 4229** at PL1/PL2/PL4 with **zero
  tests going from pass to fail**, checked as a per-id set difference. Cloud
  mode drops 91/99/1, and every one of those was cross-checked against log
  mode: none is lost detection. 104 of the 105 at PL1 fail in log mode both
  before and after — the rule under test never fired, and the earlier cloud
  "pass" was a 403 from an unrelated false positive, exactly the noise this
  file's own header warns about. Over-blocks fall at every level in both
  modes: log 26/32/34 → 25/31/33, cloud 95/248/311 → 86/235/298.

  Real WAF, enforcing: benign probes blocked went **1/6/6 → 0/3/4** at
  PL1/PL2/PL4, with the shipped default now at zero. Ten attack probes —
  SQLi and XSS through query, urlencoded body and JSON body, log4shell in an
  XML attribute, SSRF in an XML text node, RCE in a multipart form field,
  traversal in a query — are 403 at every level before and after.

  One honest narrowing: a body with no `Content-Type`, or one outside the four
  processors, is now seen through the CRS lane only by those 13 `REQUEST_BODY`
  rules. That matches upstream, where the gap is covered by 920420's
  content-type allow-list rather than by scanning everything, and prx-waf's own
  Lane 1 detectors still read the raw body regardless.

### Added

- **`[proxy] worker_threads` — the proxy data plane is no longer pinned to one
  core.** `Server::new(None)` took Pingora's `ServerConf::default()`, whose
  `threads: 1` sized the runtime every request is accepted, inspected and
  relayed on. Measured under saturation, the process held 13 OS threads and
  consumed 0.99 cores on a 16-core host, and no configuration key could change
  it; `README.md` documented a `worker_threads` key that the config struct
  carried but nothing ever read.

  It is read now. **Unset — the shipped default — the data plane follows the
  CPUs the process may use**, so an existing install gets its machine on the
  next restart without editing anything. `0` says that explicitly, `N > 0` fixes
  the count, and `PRXWAF_WORKER_THREADS` overrides it for images that serve
  several CPU budgets. The count comes from
  `std::thread::available_parallelism`, which honours the cgroup CPU quota and
  the process's CPU affinity mask — **in a container that is the quota, not the
  host's core count**, which is the number that can actually do work but will
  not match `nproc` on the host. Startup logs the effective count and where it
  came from; a single-threaded data plane on a wider host, however it arose,
  is a `WARN` naming the ceiling.

  `tests/perf/RESULTS.md` has since been re-recorded on a quiet host and is
  multi-threaded throughout. On four workers pinned to two physical cores the
  process consumes **3.88 cores** against 0.99, and proxy-only throughput on a
  small GET goes **24,987 → 58,078 rps**. The gain is sublinear, and part of the
  reason is measured rather than guessed: per-request CPU rises from 40 to
  67 µs, so the multi-threaded runtime costs about **+68% CPU per request**. How
  much of the rest is SMT and how much is contention is not yet separated — the
  controlled 1 / 2 / 4-thread sweep is listed there as not measured. One
  second-order effect is not an improvement: attack-driven memory growth rose
  from 420–750 MiB to ~4 GiB in ten seconds, because blocked requests are now
  produced 2–3× faster while the 20-connection database pool behind them is
  unchanged.

- **The CRS rules this WAF runs are now visible, and each of them can be turned
  down or off without a restart.** `OWASPCheck` compiled 285 rules out of 288
  declared and exposed nothing but the counts: there was no way to ask which
  rules were enforced, and no way to stop one of them firing short of editing
  `rules/owasp-crs/` and shipping a new deployment. The `rule_overrides` table
  migration 0007 created had no reader and no writer in any release, and
  `RulesManagement.vue` was unrouted because the endpoints it called did not
  exist — it invented four demo rules on the 404.

  `GET /api/rules/registry` now lists every enforced rule from the live checker
  — id, name, category, severity, paranoia, phase, declared action, source file
  and its effective state — alongside the load summary (declared vs enforced,
  every rejected rule and why, unreadable sources, degraded flag).
  `/api/rules/overrides` writes the two things the request path can carry out:

  - `enabled = false` — the rule is not evaluated. It cannot match, cannot
    score and produces no log line. Every write that produces one comes back
    with a `warning` field saying so in as many words.
  - `action_override = "log"` — the rule keeps running and every match is
    written to the audit log, but it contributes nothing to the anomaly score.
    This is the tuning tool.

  Overrides are global by default and can be scoped to one host
  (`host_code`), layering on top of the global decision the way
  `log_only_mode` is per-host. They are published to the request path through
  an `ArcSwapOption` as a dense per-rule state slice indexed by the rule's
  position, so a request pays one wait-free atomic load and one already-loaded
  byte per rule — and with no override configured, one atomic load and nothing
  else. Nothing is recompiled; an override changes how an already-compiled rule
  is treated.

  `prx-waf rules list` / `info` now report the rule set the daemon actually
  compiles, with each rule's effective state, instead of the CLI-only
  `RuleManager` registry the serving process never builds. `prx-waf rules
  enable` / `disable` used to resolve the id and then exit non-zero with "not
  implemented"; they write the database now, take `--host`, `--note`,
  `--log-only` and `--clear`, and refuse an id that is not in the loaded set.

  Migration 0016 makes the table safe to read: `UNIQUE (rule_id, host_id)` did
  not constrain the global rows at all, because Postgres treats NULLs as
  distinct, so one rule could carry any number of contradictory global
  overrides.

- **Bot detection is configurable at runtime.** `checks/bot.rs` was two
  compile-time `RegexSet`s, so the only way to block a User-Agent was to edit
  Rust and ship a binary. It now carries a second, operator-owned layer backed
  by the `bot_patterns` table — which migration 0007 created and nothing had
  ever read or written.

  A pattern added through `POST /api/bot-patterns` or `prx-waf bot add` is
  compiled, published to the request path through an `ArcSwapOption`, and
  matching on the **next request**; no restart, no reload of anything else. The
  request-path read is wait-free, and with no operator patterns configured it is
  one atomic load — the cost a deployment that never opens the page has always
  paid. Nothing is ever compiled on the request path: a pattern is compiled when
  it is saved (an invalid regex is a `400` naming the syntax error, never a
  stored row that fails later) and again when the set is rebuilt.

  Operator patterns are **additive**. Precedence is operator `allow` → operator
  `block` → built-in allow → built-in block, so a whitelist can clear a false
  positive the built-ins produce, and an explicit block overrides the
  search-engine bypass. Switching an individual built-in off is not possible;
  that is what `rule_overrides` is for and it remains unimplemented.

  Because operators supply the regexes, the set is bounded on the three axes
  that matter: 500 bytes per pattern, 512 enabled patterns, and a 64 KiB
  compiled-program budget per pattern (16 MiB combined). The `regex` crate does
  not backtrack, so matching is linear in the User-Agent length and independent
  of the pattern count; the limits exist to refuse patterns that ask for an
  enormous automaton, not to bound match time.

  The built-in catalogue is now data (`BUILTIN_GOOD_BOTS` / `BUILTIN_BAD_BOTS`)
  rather than an inline array of pattern strings, so the API, the admin UI and
  `prx-waf bot list` enumerate the same 32 signatures (19 allow, 13 block) the
  `RegexSet`s are built from — the listed catalogue is the running one by
  construction. Detection ids are unchanged (`BOT-001`…); operator hits report
  `BOT-USER-<id>`.

  `GET /api/bot-patterns/test?user_agent=…` evaluates a UA with the engine's own
  matcher. The admin page used to test in the browser with JavaScript's
  `RegExp`, which cannot parse the inline `(?i)` every shipped pattern starts
  with, and so reported "no match" for User-Agents the WAF blocks.

  Migration 0015 adds `bot_patterns.name`: 0007 shipped the table with a
  500-character `pattern` and a free-form `description` and no label.

- **The `audit_log` table finally has a writer, and the admin UI a page to read
  it.** The table, a `create_audit_log` function, a `GET /api/audit-log`
  handler and a 365-day retention policy had all been in place; the function
  had zero callers, so the endpoint could only ever answer `{"entries":[]}`.

  A middleware now records every state-changing admin call — who, what, from
  which address, and whether it succeeded. It sits **outside** `require_admin`
  and inside `require_auth`, so a *refused* attempt is recorded too; an audit
  trail that logs only successes hides the events most worth reviewing. Reads
  are not recorded (a dashboard polling `GET /api/status` would bury
  everything), and request bodies are never recorded — certificate private
  keys, bouncer keys, SMTP passwords and webhook URLs travel in them.

  This is not duplicated by the other trails: `security_events` and
  `attack_logs` record what traffic did, `crowdsec_events` what an external
  decision source did, and `waf-engine`'s same-named `audit_log` is a
  ModSecurity-format file recording which CRS rules a *request* matched. None
  of them answers who unblocked an IP or deleted a host — and that is the one
  question whose evidence outlives the change it describes.

### Changed

- `GET /api/audit-log` moves from the read-only route group to the admin
  group. It is a roster of administrator usernames and their source addresses,
  which is precisely what someone holding a low-privilege account wants next.
  It was harmless in the read-only group only because it returned nothing.

### Removed

- **Two admin pages that could not work are no longer reachable**: Rule Sources
  and Rule Manager. (Bot Detection was unrouted alongside them and is routed
  again above, now that it has a backend.) Their routes existed and their
  screens rendered, but no backend route did — `/api/bot-patterns`,
  `/api/rule-sources`, `/api/rules/registry`, `/api/rules/reload` and
  `/api/rules/import` all answer 404 — so each fell back to hardcoded demo
  data, and Rule Sources' built-in counts were simply invented (15/31/19
  against a real 32 bot and 36 scanner patterns). All three also called bare
  `axios` rather than the configured instance, so they carried no JWT and
  would have been rejected even if the routes had existed.

  The cause is one level down: `waf_engine::RuleManager`, the subsystem behind
  all three, is never constructed by the daemon — every reference to it is in a
  CLI subcommand. The whole `[rules]` config section is therefore dead for a
  running WAF. What actually enforces is `OWASPCheck::new()`, loading from the
  hardcoded `rules/owasp-crs`, and a compile-time `RegexSet` in `checks/bot.rs`
  with no runtime configurability at all. The `bot_patterns`, `rule_sources`
  and `rule_overrides` tables from migration 0007 have no Rust reader or
  writer either.

  The screens are kept on disk with a header explaining what connecting them
  would require, and unknown routes now redirect to the dashboard so an old
  bookmark does not land on a blank page.

- **Seven CLI subcommands stop reporting success for work they never did**:
  `bot add`, `bot remove`, `sources add`, `sources remove`, `sources update`,
  `sources sync`, and `rules enable`/`disable`. They printed a confirmation and
  exited 0; `bot add` additionally told the operator to drop a YAML file into
  `rules/`, which the daemon never reads. Each now explains what does work
  instead — custom rules, which are stored in the database and do reach the
  engine — and exits non-zero. `sources list` and `rules list` do real work and
  are untouched.

  `bot add` and `bot remove` are implemented for real above and write to
  `bot_patterns`; they say plainly that an already-running proxy keeps its
  snapshot until `POST /api/reload` or a restart, which is the difference
  between them and the admin API. `bot list` and `bot test` now read the
  running semantics — the built-in catalogue plus the operator rows, with
  precedence applied — instead of the `rules/` YAML catalogue the daemon never
  loads.

- **Notifications actually fire now.** Everything around
  `dispatch_notification` existed — config table, encrypted storage, rate
  limiter, webhook and email channels, `notification_log`, retention pruning,
  the UI with a working "test send" — and the function had **zero callers**. An
  operator could configure alerting, watch the test succeed, and never receive
  a single real one.

  `attack_detected`, `cert_expiry` and `backend_down` are wired. The event type
  and its transport live in `waf-common`, the only crate every layer can see,
  so no crate gained a dependency edge and neither `waf-engine` nor `gateway`
  was touched: every enforced block already converges on two `waf-storage`
  writes that are themselves off the hot path. Publishing is a synchronous
  `try_send` on a bounded channel that never awaits and never allocates — a
  wedged webhook endpoint cannot reach request handling — and an overflow is
  counted and logged rather than dropped in silence.

- `high_traffic` is **not** implemented and is now disabled in the UI rather
  than offered. There is no request counter to build it on:
  `AppState::increment_requests` and `increment_blocked` have no callers
  despite the comment saying the proxy layer increments them,
  `StatsCollector` has none either, and `stats_timeseries` aggregates security
  events, i.e. attacks rather than traffic. Leaving it selectable would be the
  same defect this change exists to fix.

### Fixed

- **The notification rate limiter ignored the interval it was configured
  with.** `is_rate_limited` hardcoded five minutes while `rate_limit_secs` sat
  in the database and was displayed in the UI. It was also keyed on the channel
  alone, so a flood against one host silenced alerts for every other host
  sharing that channel — an operator watching ten sites through one webhook
  would hear about the first one attacked and nothing more. It now honours the
  stored interval and buckets per (config, host), with a bound and a sweep so
  the map cannot grow without limit.

- **A notification title could inject SMTP headers.** The title reaches the
  `Subject:` header and is built from attacker-controlled request data, so a CR
  or LF in a path would have split the header. Control characters are stripped
  from titles; message bodies keep `\n` and lose everything else.

- **An ordinary file upload is no longer an attack.** A multipart file part's
  *content* was going into the surface the `ARGS`/`REQUEST_BODY` rules read, so
  the SQLi and XSS patterns ran over PDF and JPEG bytes. Measured against a
  real WAF in enforcing mode: at **PL1** a plain PDF was answered 403 by
  932130/941100/941130 and a JPEG by 933210/932130/942190; at **PL2** eight of
  nine benign uploads were blocked by **20 distinct rules**. The engine-level
  diagnostics name the bytes: CRS-942120 matched `<<` in `%PDF-1.7…<</Length 3
  0 R/Filter/FlateDeco`, CRS-942440 matched a NUL in `����\0\x10JFIF`,
  CRS-942200 matched a whole CSV row. Those byte sequences are unavoidable in
  binary content, not a coincidence — the surface was defined wrong, and it was
  never only the three rules first reported.

  No engine this rule set targets lets a file's bytes reach an `ARGS`-family
  variable. ModSecurity v2 sorts parts on whether `filename=` is present and
  `multipart_get_arguments()` has no file branch at all; Coraza sends file
  parts to a temp file or `io.Discard`; v3 does route them away too, and its
  additional raw `REQUEST_BODY` is the long-open defect ModSecurity#2146,
  reported against exactly this symptom. CRS asserts it in its own corpus:
  `942540.yaml` test 6 uploads a `text/markdown` part reading `my name is
  'foo'; and I work on CRS.` and requires 942540 **not** to fire — which also
  rules out the tempting half-measure of still scanning "text-like" uploads by
  Content-Type, since the file CRS insists must go unscanned is text.

  The split follows the origin's own parse — `filename=` is what puts a part in
  PHP's `$_FILES` instead of `$_POST`, and Rails, Django, multer and Spring key
  off it too — so a payload moved into a file part is one the application will
  never evaluate as a parameter. What it becomes instead is a stored file, and
  that is the `FILES` rules' job; they are untouched. A part whose
  `Content-Disposition` is too malformed to yield a filename is not treated as
  a file and keeps its payload on the surface.

  go-ftw, CRS v4.25.0, 4674 tests: log mode unchanged at 2779/3742/4222 with
  an **empty set difference** in the failing test ids at every paranoia level —
  removing an entire detection surface cost nothing on the corpus it was
  supposed to serve. Cloud mode moves 6 tests, each accounted for: PL2/PL4 gain
  920121-5, 933110-29 and 942540-6, all three CRS negative tests that upload
  attack-looking content and assert no rule fires; PL1 loses 933111-1/-2/-3,
  which is not lost detection — 933111 is a PL3 rule that cannot fire at PL1,
  those requests were being 403'd by the false positive itself, and cloud mode
  cannot tell one blocker from another. They pass at cloud PL2, cloud PL4 and
  log PL4, where 933111 is in scope and catches them through `FILES` as
  upstream does.

  Benign regression, enforcing, all three paranoia levels: pdf, jpg, xlsx, csv,
  a CJK filename, multi-file plus text fields, an empty file input and the CRS
  markdown case all answer 200 with no rule matched. Twelve upload attacks —
  php/jsp webshell names, `.htaccess`, traversal, double extension, SQLi and
  XSS in the filename, webshells in ordinary fields, a bogus boundary — all
  still 403. `php-webshell-name` used to match 933100/933110/933130/933160 and
  now matches only **933110**, the one rule upstream reads `FILES` for: the
  reason it blocks changed from coincidence to the upstream semantics.

### Security

- **The RUSTSEC-2023-0071 exemption is now argued against jsonwebtoken 11.0.0
  source, line by line.** It is the only entry in `deny.toml` whose case is
  "compiled but unreachable" rather than "not in the graph", so the rsa Marvin
  timing sidechannel — which has no fixed release upstream — rests entirely on
  waf-api never reaching an RSA private-key operation. That claim had only been
  checked against 10.4.0. Re-checked against 11.0.0: `from_secret` hardcodes
  `AlgorithmFamily::Hmac` behind a private field on both the encoding and
  decoding side, `decode()` rejects a mismatched `alg` header before the
  verifier factory is invoked, and `Validation::default()` is still exactly
  `[HS256]`. 11.0 is strictly tighter than 10.4: the four algorithm checks used
  to sit behind `validate_signature`, which `insecure_disable_signature_
  validation()` could switch off; that field and method are gone and the checks
  are unconditional.

  Recorded alongside it: `jws::decode` does *not* pre-check the allow-list
  before constructing a verifier, so switching to it would put attacker-chosen
  `alg` in front of the RSA verifier. Nothing in this repo uses it, and the
  exemption's reasoning now says so explicitly.

### Changed

- **jsonwebtoken 10 → 11.** `Validation` is built with struct-update syntax
  instead of field reassignment; the lint only started firing because the
  private `validate_signature` field that suppressed it was removed.
- **wasmtime 44 → 47.** No API used by `plugins/manager.rs` changed signature.
  47 enables the GC and exception-handling proposals by default, which would
  widen the bytecode a plugin may contain, but `config.rs:2519-2520` gates both
  on the `gc` Cargo feature and this build sets `default-features = false`, so
  the accepted set is unchanged. The four WASI advisories fixed in 45/46 do not
  apply — `wasmtime-wasi` is not in the tree.

### Added

- **A real multipart/form-data part parser, exposing `FILES`, `FILES_NAMES`
  and `MULTIPART_PART_HEADERS`.** Nine CRS rules that had been refused at load
  time now compile and enforce: 920120, 920121, 922120, 922130, 932180,
  933110, 933111, 933220, 944140. The two `[unsupported-field]` startup
  warnings for `unmapped_files` (5 rules) and
  `unmapped_multipart_part_headers` (2 rules) are gone. Enforced rules:
  **276 → 285** (226 request-phase, 59 response-phase).

  go-ftw v1.3.0 against CRS v4.25.0, log mode, 4674 tests, zero exclusions:
  **2744 → 2779 / 3701 → 3742 / 4176 → 4222** at PL1 / PL2 / PL4
  (89.35% → **90.33%**). Over-blocks unchanged at all three levels (26/32/34),
  verified as a per-test-id set difference rather than a count.

  The gain is +46, not the +100 the previous round predicted. That estimate
  counted each rule's whole ftw case list; in fact 57 of those cases exercise
  the `REQUEST_HEADERS:X-Filename` branch of the same rules — an upload
  filename passed as a custom header by Nginx/IIS upload modules — which needs
  a general `REQUEST_HEADERS:<name>` accessor, not a multipart parser. Of the
  cases that do go through a multipart upload, 38 of 38 now pass. 922110 (17
  cases) and 922100 (2) remain out of reach: both read `TX:` collections
  populated by another rule's `setvar`, which this engine has no store for.

  The parser is a new attack surface and is bounded accordingly:
  `MAX_BOUNDARY_LEN` 70 (RFC 2046 §5.1.1), `MAX_PARTS` 256 (each part is
  scanned like an ARGS member, so it matches `MAX_FORM_ARGS`),
  `MAX_PART_HEADER_BYTES` 8 KiB and `MAX_PART_HEADER_LINES` 32. Parts borrow
  from the body window rather than copying — which makes this cheaper than
  what it replaces, since `RequestView::new` used to run
  `String::from_utf8_lossy` over every body including binary uploads.
  "Not multipart" and "malformed multipart" are kept distinct, because
  detecting the malformed case is what rules like 920120 exist for.

### Fixed

- **A declared multipart boundary that the body never uses no longer hides the
  body from every body rule.** `multipart_payloads` returned an empty string
  for that combination, so setting a bogus `boundary=` on any request made its
  entire body invisible to inspection. A parse that yields no part now falls
  back to the whole body.

### Security

- **Three advisory exemptions retired instead of renewed.** A
  semver-compatible `cargo update` fixes RUSTSEC-2026-0190 (anyhow 1.0.104) and
  RUSTSEC-2026-0097 (rand 0.8.7), and drops RUSTSEC-2026-0173 outright: getset
  0.1.7 no longer pulls `proc-macro-error2` under the
  `pingora-cache → cf-rustracing-jaeger → local-ip-address → neli` chain, so
  the crate leaves the dependency graph. cargo-deny 0.20.2 — the version
  `cargo-deny-action@v2` actually pins, not the weaker 0.19.x a local
  `cargo install` leaves behind — reported all three as
  `advisory-not-detected` before they were deleted. Four remain, every one of
  them upstream-unfixable and argued by reachability.

- **`deny.toml` is now the single source of truth for advisory exemptions.** It
  and `.cargo/audit.toml` had drifted apart, and nothing would have reported
  it: cargo-deny fails on `unsound = "workspace"` while cargo-audit's
  `severity_threshold` + `[output] deny` never consider unsound at all, so an
  unsound-only exemption had to exist in one file and was invisible to the
  other. cargo-audit cannot read `deny.toml` and has no include mechanism, so
  the duplication is forced by the tooling; `.cargo/audit.toml` is now a bare
  ID mirror pointing back, and the `ignore-expiry` job fails the build if the
  two sets diverge.

### Changed

- **Four low-risk dependency majors:** tower-http 0.7, base64 0.23, wasmtime 44
  (fixes GHSA-p8xm-42r7-89xg, a panic when allocating a table larger than the
  host address space; the two WASI advisories in that release do not apply —
  `wasmtime-wasi` is not in the tree) and x509-parser 0.18.

  x509-parser 0.18 adds `GeneralName::Invalid` so a malformed SAN entry no
  longer aborts parsing. In `node_id_from_cert_der()` that turns a
  fail-closed into a fail-open: a leaf whose SAN holds one bad entry used to be
  rejected outright, and now the bad entry is skipped and a later well-formed
  DNS SAN still yields a node id. The `if let GeneralName::DNSName(..)` match
  compiles unchanged, so neither the compiler nor any test can catch it — it is
  recorded in `Cargo.toml` next to the version. It is bounded by rustls having
  already path-validated the leaf against our own single-level cluster CA,
  which only ever mints certificates through `NodeCertificate::generate`.

### Fixed

- **The CrowdSec bouncer no longer starts fail-open when LAPI is unreachable.**
  The decision cache is in-memory and starts empty on every process start, and
  `init_crowdsec` handed the first pull to `tokio::spawn` and returned. When
  that pull failed — container start order, a network blip, CrowdSec not up yet
  — the only trace was a `warn!`, the cache stayed empty, and `CrowdSecChecker`
  answered `None` for *every* IP: all previously banned clients allowed
  through, for as long as LAPI stayed down.

  Decisions are now mirrored into `crowdsec_decisions` (created by migration
  `0006`, written by nothing until now) and the still-valid rows are restored
  **before `init_crowdsec` returns**, i.e. before the proxy binds its
  listeners — restoring from the spawned task would leave the same race.
  Verified end to end against a real Postgres and a killed LAPI: same process,
  same database, `persist_decisions = true` answers **403 CrowdSec Ban**,
  `false` answers **200 from the origin**.

  A restored decision cannot resurrect a ban lifted while the process was
  down. Deletions in the LAPI stream are removed from the mirror by
  `(scope, value)` — the key the cache itself removes on — and every successful
  *full* pull replaces the mirror inside one transaction and evicts every
  restored cache entry the pull did not confirm.

  Also fixed in the same path: after a failed startup pull the sync loop fell
  through to *incremental* pulls, so the first success carried only the deltas
  of the last few seconds and established an incomplete baseline as if it were
  complete. Every pull is now retried as a full pull until one succeeds. A
  failed pull with an empty cache is logged at `error!` naming the fail-open
  consequence, rather than at `warn!` alongside routine polling noise.

  `crowdsec.persist_decisions` (default on) turns the mirror off for read-only
  databases or when banned client IPs must not be stored;
  `storage.crowdsec_decision_retention_days` already bounds retention.

### Added

- **Negated CRS rule heads are converted instead of dropped.**
  `modsec2yaml.py` matched `^(@\w+)` at the head of a `SecRule`, so the
  fourteen upstream rules whose head is `!@rx` / `!@within` / `!@eq` never
  reached the engine — even though `Condition.negate` had always been able to
  evaluate them, and even though one of them (CRS-954130) had previously been
  emitted as `operator: regex, value: '!@rx ^404$'`: a pattern matching that
  literal text, which could never fire. The `!` is now parsed as part of the
  operator and emitted as `negate: true`.

  Negation is only emitted for variables this engine reproduces byte for byte.
  Inverting an operator inverts the safety of every surface approximation the
  converter is otherwise allowed to make: CRS-920100 asserts that the whole
  request line is well formed, the nearest engine field (`path_raw`) holds no
  method and no protocol, so the anchored pattern never matches and the negated
  rule would have fired on *every request*. Twelve of the fourteen are
  therefore refused by name — visible in the startup WARN rather than silently
  gone — and two are shipped: **CRS-920470** (illegal `Content-Type` header)
  and **CRS-954130** (IIS information leakage, `RESPONSE_STATUS !@rx ^404$`
  chained to an ASP.NET stack trace). Enforced rules: **274 → 276** (217
  request-phase, 59 response-phase).

  go-ftw v1.3.0 against CRS v4.25.0: log mode **2739 → 2743 / 3696 → 3700 /
  4171 → 4175** at PL1 / PL2 / PL4 (89.24% → 89.32%), cloud mode **3184 → 3188
  / 3749 → 3753 / 3993 → 3997**. No test regressed in either mode; the two
  cloud-mode over-block entries that appear at PL2/PL4 are 403 before and after
  the change, by a different rule, and only moved bucket because the rule they
  name now exists.

- **The CRS response rules actually run.** `RESPONSE_BODY` and
  `RESPONSE_STATUS` are engine fields, `OWASPCheck` implements `ResponseCheck`,
  and `main.rs` registers it on the response pipeline — the three things that
  were missing between a response-inspection channel that existed and 58 CRS
  rules that had nothing to look at. Enforced rules: **216 → 274** (216
  request-phase, unchanged; 58 response-phase, new).

  Scored the way upstream scores it, which is *not* the way the request phase
  is scored. CRS 950–956 only ever `setvar:tx.outbound_anomaly_score_plN`; the
  single rule that acts is `959100`, against
  `tx.outbound_anomaly_score_threshold` = **4**, not the inbound 5. So the
  response phase gets its own accumulator and its own threshold
  (`owasp.outbound_anomaly_score_threshold`). Reusing the request-phase logic
  would have made every 95x rule its own verdict — considerably more aggressive
  than upstream, on the phase where a false positive breaks a page the origin
  considers correct.

  The verdict line is logged as `[id "959100"]`
  `Outbound Anomaly Score Exceeded (Total Score: N)`, upstream's wording, which
  is what the CRS corpus asserts on.

  **Enforcement stays opt-in.** The default is observe: log the finding, deliver
  the response. `PRXWAF_RESPONSE_INSPECT_MODE=enforce` withholds the bytes and
  aborts the stream instead (it cannot answer 403 reliably — see
  `crates/gateway/src/response.rs`).

- **Rule-hit audit log (`[audit_log]`, off by default).** `security_events`
  records the verdict — one row, one rule, the heaviest contributor. Since
  anomaly scoring landed, a request can match three rules and still be allowed,
  and nothing recorded it. The audit log writes one line per matched CRS rule
  plus one for the anomaly-score verdict, in ModSecurity's bracketed
  `[id "942100"] [msg "..."] [severity "..."] [score "..."]` error-log shape, so
  a threshold or a paranoia level can be tuned from evidence.

  Enabling it opens a file, so it is opt-in. Writes go through a bounded
  channel to a single background task — the request path never waits on the
  disk, and a flood drops records (counted, logged) rather than applying
  back-pressure to traffic. Only request *metadata* is recorded (client IP,
  host, method, URI path — the set `attack_logs` already stores); the query
  string is opt-in via `include_query` and the matched data is never written.
  Every attacker-controlled value is sanitised before it reaches a line, so a
  crafted URI cannot forge a log line or a rule id. `max_size_mb` /
  `keep_rotations` bound the disk cost and the lifetime of that metadata.

- **`audit_log.marker_header`** echoes a chosen request header to the log and
  suppresses that request's own rule lines — the same contract as upstream CRS's
  test-marker rule `999999` with `ctl:ruleRemoveById=1-999999`. Setting it to
  `X-CRS-Test` is what lets `go-ftw` run against prx-waf in **log mode**.

- **`[[hosts]] log_only_mode`** in the config file. Detect but do not enforce
  (`SecRuleEngine DetectionOnly`). The flag already existed on API-created
  hosts; it was unreachable from a config file.

### Fixed

- **`crs_id` was silently discarded.** Every generated file in
  `rules/owasp-crs/` carries `crs_id: 942100`, and the CRS rule struct had no
  such field, so serde dropped all of it — leaving the engine unable to name a
  rule the way every other CRS tool does. It is now parsed (and recovered from
  the `CRS-` prefix for files that predate the key).

### Changed

- **Enforceable CRS rules: 274 of 284** (9 rejected at load and named
  individually in the startup `WARN`, plus one field/operator mismatch). Was
  216 of 328 while the response rules were rejected as unevaluable, and 215
  before per-parameter `ARGS` — evaluating `ARGS` per parameter made
  `CRS-942130`'s chained `TX:1 @streq %{TX.2}` mean what upstream means (the
  equality is only a tautology when the head sees a whole query string, where
  the `name=value` separator forms it by itself), so that rule is enforced
  instead of refused. The declared count fell from 328 to 284 because an
  earlier converter generation shipped the 950/951/955 sets **twice**
  (`CRS-95xxxx` and `CRS-RESP-95xxxx`); the duplicates were dropped, so no
  response rule can contribute its severity to the outbound score twice.
  `RESPONSE-953/954/956` are now generated by `modsec2yaml.py` like the rest,
  which adds `953101`. `954130` is not converted: its `!@rx` head is a gap in
  the converter, which now says so on stderr instead of dropping it silently
  (the previous generation emitted it with `!@rx ^404$` as the *regex*, a rule
  that could never match). The counts are asserted in
  `waf-engine::checks::owasp::tests::shipped_crs_inventory_is_fully_accounted_for`,
  which is the number to quote; the figures in the released sections below
  are the state as of those releases.

- **The CRS regression harness (`tests/ftw/`) runs in either mode.**
  `MODE=log` (new default) runs the corpus as written with the WAF in
  DetectionOnly and takes its verdicts from rule ids in the audit log — the
  posture ModSecurity v2 + CRS and Coraza are measured in. `MODE=cloud` keeps
  the previous status-code behaviour. Measured at `c3eb2dd`, CRS v4.25.0,
  4674 tests: log mode **57.15% / 77.41% / 87.57%** at PL1/PL2/PL4, cloud mode
  68.12% / 80.21% / 85.43%. `baseline.json` is keyed by mode, and CI runs both.

  With the response phase wired: log mode **58.60% / 79.08% / 89.24%**
  (+68 / +78 / +78 tests, all of them response-phase, zero tests lost). Cloud
  mode is unchanged at 68.12% / 80.21% / 85.43% — by construction, since the
  default observe posture never changes a status code and cloud mode reads
  nothing else. `PRXWAF_RESPONSE_INSPECT_MODE=enforce` takes cloud PL4 to
  86.01% (+27, zero lost), which is a note in `baseline.json` and not the gate.

- **`tests/ftw/classify.py` no longer files response-phase failures under
  `not-implemented`.** Its reason — "the engine never feeds it a response body"
  — has stopped being true, and a bucket that absorbs every response failure
  would hide the regressions the harness exists to catch. They are now counted
  as ordinary missed detections / over-blocks / paranoia-scope exclusions.

---

## [0.2.31] — 2026-07-25

This release finishes the retention rollout (all nine accumulating tables
now covered), closes further CRS/regex decoding gaps, rewrites Lane 1's
structural shell-injection judgment (false positives on ordinary traffic
drop sharply), and fixes a licensing gap. It does **not** contain the
cluster or notification changes below — those already shipped in 0.2.29
and 0.2.30; see those sections if you are jumping straight to 0.2.31 from
an older release.

### Security

- **Regex-based CRS rules bypassed via encoding.** 308 of 352 shipped CRS
  operators are regex, and regex was matched against the raw, undecoded
  request while only `@pm`/SQLi/XSS operators saw decoded input.
  `${jndi:` written as `%24%7Bjndi%3A`, a double-encoded payload, and an
  encoded `php://` wrapper all passed the entire regex ruleset before this
  fix; confirmed 200 → 403 against a running proxy for all three. Decoding
  is now chosen per request surface to match how the origin parses it —
  path, query, body and cookies decode; headers, User-Agent and Referer
  intentionally do not (decoding those introduces its own false
  positives, e.g. a Referer carrying a literal `%5B0%5D`).
- **Chained CRS rules only evaluated their first condition.** 18 shipped
  rules are chains upstream (a match followed by further conditions on
  the same value or a capture group); the converter kept only the head,
  so every one was looser than intended — `CRS-944110` reduced to "any
  log line mentioning the Java runtime", `CRS-931130` to "any parameter
  holding `scheme://`" (i.e. any OAuth `redirect_uri`). Chains are now
  evaluated in full; a condition the engine cannot express rejects the
  whole rule by name instead of running a weakened head.
- **CRS transformation (`t:`) directives were parsed and discarded.**
  Rules were evaluated against an approximated surface instead of the
  form they actually target, causing both false negatives (`t:lowercase`
  never applied, so a real `InvokerTransformer` went undetected on 46
  rules while its lowercase spelling did not) and false positives
  (`CRS-920230`, which expects a double-decoded value, instead fired on
  plain `q=100%25`). Rules now apply their declared transformation chain,
  in order, before matching; an unsupported transformation is rejected by
  name at load time rather than silently approximated.
- **Shell-injection detection missed common obfuscation.** Lane 1 (the
  regex/structural checkers) matched injected command chains as literal
  text, so brace expansion (`cat /etc/{passwd,shadow}`) and ANSI-C
  quoting (`$'\x63\x61\x74'`, `${!x}`) were invisible to all three
  detection layers. These are now expanded/decoded the way a shell would
  before matching (brace expansion bounded to 16 results, compared
  against the same sensitive-path list as before — the match surface does
  not widen). A new structural rule also catches bare command-separator
  chains (`;`, `&&`, `|` followed by a lowercase executor with arguments)
  that keyword lists missed; a single match of this rule alone cannot
  trigger a block (weighted at exactly half of the block threshold).

### Changed (breaking / behavior)

- **`LICENSE` renamed to `LICENSE-APACHE`; `LICENSE-MIT` added.** The
  crate has advertised `MIT OR Apache-2.0` since the first release but
  the repository only ever shipped the Apache text under a bare
  `LICENSE`. Any tooling or automation that reads the license by the
  literal path `LICENSE` will break — update references to
  `LICENSE-APACHE` (or `LICENSE-MIT`, now present for the first time).
- **Lane 1 structural checkers rewritten to judge shape, not vocabulary
  — false-positive rate on ordinary traffic drops sharply.** A live-proxy
  probe of 60 ordinary business requests found 35 answered with 403
  before this release: `TRAV-007` blocked any absolute path containing a
  common directory name (so a site serving `/home` or
  `/dev/api/v1/status` blocked its own routes), and `RCE-001` treated any
  separator next to a case-insensitive word from its list as command
  injection — flagging `name | id | email` field lists, markdown inline
  code, `$(document).ready()`, book titles containing "JavaScript", and
  ordinary curl examples in documentation. The same 60-request probe now
  returns 1 false positive. Detection did not get weaker: `?id=1; DROP
  TABLE users--`, previously missed entirely, is now caught, and a
  50-probe attack corpus has zero misses. **If anything downstream was
  written to tolerate or work around the old over-blocking behavior of
  Lane 1, that workaround is no longer needed and that traffic now passes
  through as normal.**
- **Retention pruning now covers all nine accumulating tables** (up from
  five as of 0.2.30): `crowdsec_decisions`, `refresh_tokens`,
  `notification_log` and `request_stats` are newly covered. Each keys on
  the column that reflects when the row actually stopped mattering
  (`expires_at` for decisions/tokens, `period_start` for stats); a
  revoked refresh token is deleted immediately regardless of its window,
  and a decision with no known expiry is left untouched rather than
  guessed at. As with the tables added in earlier releases, defaults are
  configurable under `[storage]` and `0` retains a table's history
  indefinitely.
- CRS rules now carry their declared surface's transformation and
  decoding behavior; the total number of rules the engine can enforce is
  unchanged by this release (215 of 328 as of 0.2.31, see 0.2.30 — it is
  216 since the per-parameter `ARGS` change, recorded under Unreleased),
  but which specific traffic those rules match against has changed per
  the Security entries above — expect some previously-passing encoded or
  obfuscated payloads to now be caught, and some previously-blocked
  plain-text lookalikes to now pass.

### Fixed

- CI's database-dependent `waf-storage` test suites (retention,
  observation round-trip, INET address handling) are now actually
  executed against a real Postgres instance in CI. They previously
  existed only as `#[ignore]`d tests that no CI job invoked — including
  the retention logic shipped across 0.2.29–0.2.31, which had never run
  anywhere but a developer's machine before this fix.

### Performance

- Encoded-traffic detection got cheaper after the transformation-chain
  fix above, since a request is now matched against exactly one derived
  form instead of approximated across three: five-layer-encoded input
  drops from 3.27ms to 0.37ms. Plain-text requests cost about 11% more,
  reflecting the lowercasing/command-line-folding work that was
  previously being skipped rather than performed.
- The brace-expansion/quoting decode step for shell-injection detection
  is a word-at-a-time scan (a naive byte-by-byte scan cost 125µs on a
  2 KB query, judged too expensive); plain-text cost from this change was
  not separately measured but is reported as not measurable in the
  20-benign-probe verification run.

---

## [0.2.30] — 2026-07-25

### Security

- **Cluster election forgery.** Any node holding a valid cluster
  certificate could broadcast a fabricated, unsigned election result
  (`term: u64::MAX`, itself as winner, no real votes) and be accepted as
  the cluster main — whatever it then pushed (rules, configuration)
  passed the existing "is this the main" gate, letting one compromised
  worker rewrite the WAF policy of the entire cluster. A result is now
  accepted only if the receiving node itself voted for the winner in
  that exact term, the winner is a declared member, and the provable
  votes reach a real majority; an unverifiable-but-plausible claim can
  make an incumbent main step down without adopting the claimant's term
  (a re-join loop then recovers the legitimate main), but can never grant
  authority outright. Terms can no longer be pinned at `u64::MAX`
  (advances are capped at 1024 per message), non-main nodes can no
  longer answer join requests with a CA key, and node certificates now
  declare key usage and EKU. **Breaking:** join tokens now carry a format
  version, and tokens minted before this release (v1) are rejected
  outright with "unsupported join token version" — **re-issue join
  tokens for any node you plan to add to a cluster after upgrading.**
  New tokens also carry a per-token nonce with server-side replay
  tracking and can be bound to a specific node id. A minority-split
  forgery against nodes that genuinely voted for the attacker is still
  possible; closing that needs signed quorum certificates and is not
  done in this release.
- **CRS `Field::All` header over-matching.** 170 CRS rules were scoped to
  scan every request header (`Field::All`) because the rule converter
  fell back to that whenever it could not map an upstream variable, even
  though only 22 of those rules actually target `REQUEST_HEADERS`. A
  live-proxy probe found 9 of 11 ordinary requests blocked at paranoia
  level 1 as a result — `CRS-941130` fires on the word "xhtml", which
  every browser sends via `Accept: application/xhtml+xml`; `CRS-933150`
  fires on the PHP function name `urlencode`, which every form POST
  sends via `Content-Type: application/x-www-form-urlencoded`. A browser
  could not load a page through this WAF with `owasp_set` enabled. Rules
  are now scoped per-rule against upstream CRS v4.25.0 (no rule gained a
  surface it did not already have); 8 rules whose upstream variable the
  engine cannot reach at all (upload filenames, multipart part headers, a
  header-count test, two chained capture comparisons) are now rejected by
  name instead of scanning everything, and the converter no longer falls
  back to `Field::All` for an unmapped variable. Verified against a
  running proxy: false positives 9 → 0, all 13 attack probes still
  blocked. **Enforceable CRS rules move from 224 to 215 of 328** as a
  result of this fix (113 rules were from then on explicitly rejected at
  load and named individually in a startup `WARN`, versus the previous
  silent mismatch). Both figures are the state as of 0.2.30; the current
  count is under Unreleased.

### Changed (breaking / behavior)

- **Retention pruning extended from one table to five.** Added
  `security_events`, `attack_logs`, `audit_log`, and `crowdsec_events` —
  none of which previously had any pruning caller, so a default
  deployment retained every client IP address indefinitely. Default
  windows: 90 days for the attack-telemetry pair (kept in sync, since
  they're two views of the same incident), 365 days for the audit trail,
  30 days for the CrowdSec echo (its authoritative copy lives in the
  LAPI). Configurable under `[storage]`; deletes run in bounded batches
  against the `created_at` index so a large existing backlog does not
  hold the database for minutes on first run. Four more tables were
  covered in 0.2.31 (see that section) and one more (`semantic_observations`)
  already had its own pruner as of 0.2.29.

---

## [0.2.29] — 2026-07-25

### Added

- Tag-triggered release pipeline: builds the Admin UI, gates on
  fmt/clippy/test, cross-builds for x86_64 and aarch64, and publishes
  signed release tarballs with a CycloneDX SBOM and SLSA build
  provenance (cosign keyless signing via GitHub OIDC — no long-lived
  signing key is stored in the repository).
- `SECURITY.md` disclosure channel and response timeline (previously the
  project had none), plus OpenSSF Scorecard and Dependabot workflows.
- `CHANGELOG.md` entries reconstructed for 0.2.1 through 0.2.28; every
  prior release had been folded into a single "Unreleased" section with
  no per-version notes for the new release pipeline to extract from.

### Security

- **Three request-parsing bypasses of the detection pipeline:**
  - Repeated headers were flattened with last-value-wins, so only the
    final value of a duplicated header name reached the detectors.
    Header values are now folded the way the origin reassembles them,
    bounded at 64 values and 32 KiB per name; a request that exceeds
    that bound, or carries a duplicate `Host` header, is now refused
    rather than silently truncated. `X-Forwarded-For` is now read across
    every occurrence of the header instead of only the last one.
  - A payload split across two `Cookie` header lines was scanned as if
    only the second line existed, while the origin reassembles both per
    RFC 6265.
  - URL whitelist matching decoded the path once and never normalized
    dot segments, so `/static/..%2f..%2f..%2fetc/passwd` matched a
    `/static` whitelist prefix and skipped every detection phase. Paths
    are now decoded to a fixed point and normalized per RFC 3986; a path
    whose structure changes under decoding no longer qualifies as
    whitelist-eligible at all. **Breaking:** whitelisting a URL no longer
    skips CrowdSec, the community blocklist, GeoIP, or rate limiting —
    only WAF rule matching is skipped for a whitelisted path. Previously
    all four checks were bypassed, which made any whitelisted prefix a
    free denial-of-service channel; deployments that whitelisted a path
    expecting it to also skip rate limiting will now see that path rate
    limited.
- **Body inspection changed from a partial preview to full windowed
  inspection.** Bodies were previously inspected for their first 64 KiB
  only, with the remainder forwarded unread — 64 KiB of filler could hide
  an attack payload placed after it. Bodies are now inspected in
  overlapping windows across their full length, with bytes withheld from
  the origin until their window is confirmed clean. **Breaking:** by
  default, a body larger than 10 MiB is now rejected with `413` rather
  than let through uninspected; configurable via
  `PRXWAF_BODY_INSPECT_MAX_BYTES` (byte ceiling, `0` = unlimited) and
  `PRXWAF_BODY_INSPECT_OVERFLOW` (`reject`, the default, or `log`).
  **Deployments that accept uploads larger than 10 MiB must review this
  setting before upgrading**, or those uploads will start being
  rejected.
- Lane 2 (the semantic engine) could be switched off by an attacker via
  two counters under their control: a degraded request zeroed its whole
  verdict instead of abstaining only on the unchecked part, and token
  normalization split on whitespace before truncating to 64 bytes — which
  does nothing for headers, query strings or cookies (no whitespace), so
  the entire value was one token and only its first 64 bytes were ever
  seen. Header-scope views now use an 8 KiB per-token / 32 KiB per-view
  ceiling; body scope keeps its 64-byte cap. A degraded request now
  abstains on the unchecked part rather than discarding signals Lane 1
  already observed.
- **Notification channel credentials were stored and served in
  plaintext.** SMTP passwords, webhook secrets and Telegram bot tokens
  were stored as plaintext in `config_json`, and `list_notifications`
  returned the column verbatim to any authenticated user. A Telegram
  transport failure was worse than the column itself: the rendered
  request URL (containing `bot<TOKEN>`) was logged to `notification_log`
  and shown in the Admin UI. Credentials are now encrypted at rest with
  the same master-key path CrowdSec uses; API responses carry a
  `password_set` boolean instead of the value, and transport failures
  report a category only. Existing plaintext rows are upgraded
  transparently on next save. **Breaking:** both notification routes
  move from the `readonly` role group to `admin` — a `user`-role token
  that previously had read access to notification configuration now
  gets `403`.
- `waf-api` error handlers in the tunnels, CrowdSec, security, and
  notifications routes previously returned raw `e.to_string()` values,
  which for SQL errors exposed table/column/constraint names and for
  CrowdSec exposed the internal LAPI address. These now go through
  `ApiError`; input-validation error text is unaffected.
- Of 328 shipped CRS (OWASP Core Rule Set) rules, only 248 could ever
  match — rules naming a field with no accessor, or using an unsupported
  operator, compiled successfully and were counted as active but every
  match arm tested them with `is_some_and`, so they were permanently
  false and mostly logged nothing. Unsupported fields/operators are now
  rejected explicitly at load with a startup warning naming the rule and
  the reason; three new operators (`pm_from_file`, `contains_any`,
  `equals`) and five new fields were also implemented, taking active
  rules to 279 (re-scoped down in later releases as further gaps were
  found — see 0.2.30 and 0.2.31 for the current count).
- 54 `RESPONSE-95x` CRS rules across six rule files, plus `CRS-950100`,
  were tagged with the wrong field (`field: body` / `field: all`) so
  patterns meant to catch error text leaking out of an origin server
  instead ran against incoming request data — a request body starting
  with a shebang, the text "we call SQLBindCol here", or posting
  `<title>Tiny File Manager</title>` were all blocked at paranoia level
  1, and any request whose body was 500–599 bytes was blocked outright
  by `CRS-950100`. These 55 rules are now correctly scoped to
  `response_body`/`response_status`, which the engine does not yet
  evaluate — they are rejected at load with a startup warning rather
  than misfiring. Active CRS rules go from 279 to 224 (further re-scoped
  in 0.2.30 — see that section for the number that ships). The root
  cause was in the rule converter, which mapped any unrecognized
  ModSecurity variable to the widest possible scan; the missing
  variables are mapped explicitly now.
- The startup log claiming Lane 2 enforcement "would be treated as
  log_only" was stale — it no longer reflected the enforce-block code
  path that had already landed, so an operator turning enforcement on
  could be told they were still in shadow mode while requests could
  already be answered with `403`. Startup now reports the resolved
  per-family mode, the canary and circuit-breaker gates, and a verdict
  line stating whether the process can block and what is preventing it.
  Semantic observations gained a retention pruner (default 30 days,
  configurable, `0` retains indefinitely) — the table previously had no
  cleanup caller and grew without bound.

### Fixed

- The build-status badge in `README.md` was a static "build passing"
  image that stayed green through 40 consecutive failing CI runs. It now
  points at the real GitHub Actions workflow status, plus a badge for
  the new security-audit workflow.

---

## [0.2.28] — 2026-07-25

### Fixed

- Fixed a clean-checkout build failure in `waf-api`: the embedded admin-UI
  asset directory was entirely excluded by `.gitignore`, so a fresh clone
  failed to compile before the frontend was built. CI now builds the
  frontend before `cargo build`, so release binaries embed the real Admin UI
  instead of a placeholder.

---

## [0.2.27] — 2026-07-25

### Fixed

- Fixed a clippy lint failure (`question_mark`) introduced by a newer Rust
  toolchain that could block CI's lint gate from ever reaching the
  test/build/db-parity jobs. No runtime behavior change.

---

## [0.2.26] — 2026-07-24

### Security

- Closed false-negative gaps in the structural SSTI and LDAP-injection
  detectors, and a reflected-XSS gap involving window-scoped event-handler
  payloads reparsed inside an HTML frameset.
- Request bodies encoded as UTF-16 with a byte-order mark are now
  transcoded to UTF-8 before inspection — previously such bodies (including
  XXE payloads) could bypass detection entirely.

---

## [0.2.25] — 2026-07-24

### Added

- A read-only Admin UI panel for Lane 2 semantic-detection telemetry
  (shadow-mode observations), so operators can review what the semantic
  engine would have detected or blocked before switching an attack family
  from shadow to enforce.

---

## [0.2.24] — 2026-07-24

### Changed

- Internal quality hardening for the Lane 2 semantic engine: fixed edge
  cases in the confidence-scoring boundary math and added a large
  blind-negative regression corpus and table-driven detector tests. No
  detection behavior change for previously-passing traffic.

---

## [0.2.23] — 2026-07-24

### Security

- Closed detection gaps (false negatives) in the structural deserialization,
  XPath-injection, and LDAP-injection detectors, and widened the SQLi
  information-disclosure rule to recognize probes against any database
  catalog view, not just `information_schema`.
- base64-wrapped deserialization and XXE payloads were previously held back
  from detection by an over-cautious confidence gate; they now surface
  correctly.

### Fixed

- Reduced false positives in the same batch of deserialization,
  XPath-injection, and LDAP-injection detectors.

---

## [0.2.22] — 2026-07-24

### Added

- A new shadow-only detector for HTTP request-smuggling patterns
  (conflicting/ambiguous `Content-Length` / `Transfer-Encoding` framing),
  evaluated at the gateway header phase as part of the Lane 2 semantic
  engine.

---

## [0.2.21] — 2026-07-24

### Added

- A new opt-in structural detector for unsafe deserialization payloads
  (e.g. Java/PHP/Python serialized-object injection), part of the Lane 2
  semantic engine. Shadow-only and off by default, like the other Lane 2
  detectors.

---

## [0.2.20] — 2026-07-24

### Added

- A new opt-in structural detector for XPath injection, part of the Lane 2
  semantic engine.

---

## [0.2.19] — 2026-07-24

### Added

- A new opt-in structural detector for LDAP injection, part of the Lane 2
  semantic engine.

---

## [0.2.18] — 2026-07-24

### Security

- Extended the RCE detector to catch command execution via interpreter
  "exec flags" (e.g. `python -c`, `perl -e`), a pattern it previously
  missed.

### Fixed

- Narrowed two SQLi false-positive sources: legitimate `information_schema`
  queries and hex-literal values were being flagged.
- Per-host defense configuration (which detectors and enforcement modes
  apply to a given host) is now correctly wired through the full runtime
  request path — some code paths previously ignored per-host overrides.

---

## [0.2.17] — 2026-07-24

### Added

- A new opt-in structural detector for Server-Side Template Injection
  (SSTI), part of the Lane 2 semantic engine.

---

## [0.2.16] — 2026-07-24

### Added

- A new opt-in structural detector for NoSQL injection (e.g. MongoDB
  operator injection), part of the Lane 2 semantic engine. Operator-key
  extraction is restricted to an allowlist, and the higher-risk `$expr`
  operator ships disabled by default to limit false positives.

---

## [0.2.15] — 2026-07-24

### Added

- A new opt-in structural detector for XML External Entity (XXE)
  injection, part of the Lane 2 semantic engine.

---

## [0.2.14] — 2026-07-23

### Added

- The Lane 2 semantic engine now parses structured request bodies
  (JSON/XML/GraphQL/form fields) field by field instead of treating the
  body as an opaque blob, improving detection accuracy for attacks
  embedded in structured payloads.

### Security

- Fixed a stack-overflow denial-of-service in GraphQL body parsing,
  triggerable by deeply nested queries; nesting depth is now bounded by an
  accurate lexer-level guard.
- XML numeric character references (e.g. `&#x27;`) in request bodies are
  now decoded before semantic inspection, closing an encoding-based
  evasion gap.

---

## [0.2.13] — 2026-07-23

### Added

- Automatic retention pruning for stored Lane 2 semantic-detection
  observations, preventing unbounded database growth.

---

## [0.2.12] — 2026-07-23

### Added

- A shell-AST (Bash-parser-based) RCE detector that corroborates the
  existing RCE detection signals for higher-confidence blocking decisions.

### Security

- Fixed a stack-overflow denial-of-service in the new shell-AST parser,
  triggerable by deeply nested command substitution in request content;
  parsing is now depth-guarded.

---

## [0.2.11] — 2026-07-23

### Security

- Fixed missed detections (false negatives) in the semantic XSS detector:
  certain event-handler payloads reparsed inside an HTML frameset were not
  caught, and a base64-decode path mishandled the `+` character.

### Fixed

- Fixed a false-positive source in the semantic XSS detector where
  frameset-suffix reparsing could be tricked by HTML comment/RCDATA/RAWTEXT
  wrapping into flagging benign content.

---

## [0.2.10] — 2026-07-23

### Added

- The Lane 2 semantic engine (SQL injection, RCE, path traversal, XSS) can
  now actually block matching requests instead of only logging them.
  Blocking is opt-in: the shipped default configuration remains shadow-only
  (`log_only`). Operators enable blocking globally via
  `content_security.enforcement_mode = "enforce"`, or per attack family via
  the new `enforcement_overrides` setting (e.g. enforce SQL injection only,
  keep the rest in shadow).

### Security

- A block decision backed solely by a "blind"/synthetic detection view
  (no directly observable evidence) is downgraded to a log event, so
  ambiguous provenance can never single-handedly trigger a block.

---

## [0.2.9] — 2026-07-23

### Added

- A second XSS signal source (JavaScript-token analysis) that corroborates
  with the existing DOM-based XSS detector for higher-confidence
  detection. Shadow-only, like the rest of the Lane 2 engine at this
  point.

---

## [0.2.8] — 2026-07-23

### Added

- A DOM-aware (HTML5-parser-based) semantic XSS detector, part of the
  Lane 2 engine. Shadow-only and off by default.

---

## [0.2.7] — 2026-07-23

### Fixed

- Fixed host create/update passing `remote_ip` as plain text instead of
  casting it to the database's `inet` type, which could fail or silently
  mis-store the value.

---

## [0.2.6] — 2026-07-23

### Added

- The Lane 2 SQL-injection detector now also runs a full SQL-parser
  (AST-based) analysis pass for higher-confidence detection, in addition
  to its existing structural checks. Still shadow-only.

---

## [0.2.5] — 2026-07-23

### Added

- Two more opt-in Lane 2 semantic detectors: remote command execution
  (RCE) and path traversal. Same shadow-only, off-by-default posture as
  the SQL-injection detector.

---

## [0.2.4] — 2026-07-22

### Fixed

- Per-host `log_only_mode` (shadow mode) set via the Admin API or config
  was not actually applied to the running host configuration on create,
  update, or startup — it now takes effect immediately.

---

## [0.2.3] — 2026-07-22

### Changed

- The shipped `configs/default.toml` now enables the Lane 2 semantic
  SQL-injection detector by default, in shadow mode (`log_only`) — it
  observes and logs matches but never blocks traffic. A fresh install with
  no config file still ships with it off. Measured zero false positives
  and full detection on the project's internal bypass corpus before this
  default flip.

---

## [0.2.2] — 2026-07-22

### Added

- A new opt-in structural SQL-injection detector, the first real detector
  in a new "Lane 2" semantic content-security engine that sits alongside
  the existing regex-based rules. Disabled by default; when enabled it
  only observes and logs matches — it never blocks.

---

## [0.2.1] — 2026-07-22

A large security-hardening release consolidating a full-codebase audit
(7 crates, ~27K LOC) together with several new features. The headline fix
is the WAF detection pipeline not running at all for GET/bodyless
requests — see the notes below before upgrading, several conditions now
refuse to start the process.

### Security

#### WAF detection engine

- Fixed WAF inspection never running on GET / bodyless requests: the
  per-request context was only ever built in the upstream-selection phase,
  which runs *after* the request-filter phase — so the request filter
  always saw no context and let every request without a body through with
  zero checks (SQL injection, XSS, RCE, path traversal, IP/URL
  blocklists, rate limiting, and GeoIP were all bypassed). Detection now
  runs during the request-filter phase; empty-body POST/PUT requests are
  now inspected too. **This is the most impactful fix in this release.**
- Aligned the HTTP/3 request path with HTTP/1.1: unknown hosts no longer
  pass through unchecked, backend selection now honours per-host routing
  instead of a hardcoded loopback target, and request/response headers are
  no longer silently dropped.
- Header-based attacks were previously invisible to the WAF: a curated set
  of request headers (User-Agent, Referer, X-Forwarded-For, etc.) is now
  scanned for SQL injection/XSS/RCE; directory-traversal detection is
  unified to also cover the request body and cookies with recursive
  decoding.
- The configured CrowdSec AppSec `failure_action` (Block/Log/Allow) is now
  honoured instead of always treating an unavailable AppSec backend as
  allow. Note that the default is still `allow`, and that fallback is
  currently silent — set `failure_action` explicitly if you need to know
  when AppSec protection is unavailable.
- The SQL injection, XSS, RCE, directory-traversal, scanner and bot
  detectors now fail closed instead of open when their pattern set fails
  to compile, as does GeoIP when it cannot resolve a client's country in
  allow-only mode. The OWASP ruleset loader and the sensitive-data
  detector still fail open on a load error.
- URL blocklist entries and the custom-rule `Path` field are now matched
  against the decoded path as well as the raw one, closing a single-encoded
  bypass (e.g. `/%61dmin`). Decoding is applied once, so double-encoded
  paths (`/%2561dmin`) are not yet covered, and custom-rule fields other
  than `Path` are still matched against raw values.
- Custom rules now honour their configured `action` (Allow/Log/Block)
  instead of always blocking on match; custom-rule regexes are precompiled
  once at load time instead of per request.
- Fixed connection-rate-limit counting each request-with-body twice (once
  at the header phase, once at the body phase), which had halved the
  effective rate limit for POST/PUT traffic.
- `X-Forwarded-For` now uses the right-most (server-appended) entry
  instead of the client-controlled left-most one, closing an IP-spoofing
  gap in IP-based rules and rate limiting.
- Non-default ports are now rejected on the bare-host routing fallback,
  closing a host/port routing ambiguity.
- Deprecated the DNS-rebinding-vulnerable bare URL validator as a
  regression-guard only; production SSRF-guarded call sites (webhooks,
  remote rule sources) already use the IP-pinned variant.

#### Admin API

- Added RBAC: write/sensitive Admin API routes are now gated by an
  admin-only check. A logged-in but non-admin user can no longer delete
  hosts, issue cluster join tokens, upload WASM plugins, or change
  CrowdSec configuration.
- Startup now rejects a weak `JWT_SECRET` (empty, shorter than 32
  characters, a known placeholder value, or low entropy).
- Added end-to-end TOTP two-factor authentication (RFC 6238, ±1 time-step
  window, constant-time comparison, replay protection) with a two-step
  self-service enable/verify/disable flow.
- Tightened CORS: an empty `cors_origins` no longer allows any origin.
- The Admin API no longer leaks internal/database error detail to
  clients; details are logged server-side instead.
- Added a global request body size limit and a 16 MiB cap on WASM plugin
  uploads.
- The login/logout/refresh endpoints are now covered by the admin IP
  allowlist (`/health` stays unguarded for liveness probes).
- Tunnel auth tokens are now compared in constant time; the
  `Authorization` header is preferred over the `?token=` query parameter
  for tunnel WebSocket auth (query-parameter auth is now deprecated).

#### Cluster

- Cluster protocol messages are now bound to the authenticated mTLS peer
  certificate, preventing a peer from forging another node's ID in
  heartbeats or election votes.
- The join token is now actually validated on the main node before
  accepting a join request (it was previously never checked in
  production); encrypted CA-key replication is now gated behind an
  explicit opt-in, default off.
- Added a frame-size cap on the cluster transport to prevent an
  out-of-memory DoS from an oversized length-prefixed frame.
- Election quorum now uses a fixed, configured member set instead of the
  live (evictable) peer view, closing a split-brain window during network
  partitions.
- CA-key and encrypted-field-at-rest key derivation moved from unsalted
  single-round SHA-256 to Argon2id with a random per-blob salt (legacy
  blobs remain decryptable for migration).
- Cluster lz4 snapshot decompression is now capped at 256 MiB to prevent
  a decompression-bomb DoS.

#### Storage / community threat intel

- Fixed CrowdSec configuration "upsert" silently inserting a duplicate row
  instead of updating — every CrowdSec configuration change had
  previously been a silent no-op, and reads always returned the oldest
  row.
- Community blocklist integration hardening: initialization now fails
  closed when a configured signing key is invalid; per-detection signal
  reporting moved off unbounded background tasks onto a bounded queue to
  prevent a task-spawn storm under DDoS; community-server HTTP responses
  are now streamed with an 8 MiB cap instead of buffered fully in memory;
  blocklist snapshots are now verified with Ed25519 signatures before use.
- Community delta-sync hardening: delta payloads now use the
  cryptographically verified payload field instead of trusting the
  top-level unsigned JSON, closing a signature-replay/tampering gap; size
  limits were added to the version and signing-key responses.

### Added

- ACME auto-TLS: certificates for configured SSL hosts are now
  automatically issued and renewed, and the ACME HTTP-01 challenge path is
  actually served.
- Self-service TOTP endpoints: `POST /api/account/totp/{setup,verify,disable}`.
- An environment-variable override layer for security-critical settings
  (`DATABASE_URL`, `PRXWAF_TRUST_PROXY_HEADERS`, `PRXWAF_TRUSTED_PROXIES`,
  `PRXWAF_CLUSTER_JOIN_TOKEN`, `PRXWAF_CLUSTER_MEMBERS`,
  `PRXWAF_CLUSTER_SEEDS`, `PRXWAF_CLUSTER_REPLICATE_CA_KEY`,
  `PRXWAF_CLUSTER_AUTO_GENERATE`, `PRXWAF_CLUSTER_CA_PASSPHRASE`) so
  operators can configure everything without touching TOML. A new
  `.env.example` documents them, and the shipped `docker-compose.yml` /
  `docker-compose.cluster.yml` no longer ship a default `JWT_SECRET`.
- Opt-in IP-feed threat intelligence: ingest external CIDR blocklists
  (ET Open, the Tor exit-node list, Spamhaus DROP) on a per-feed schedule
  with SSRF-guarded, IP-pinned fetching. Disabled by default; shipped
  config includes license-annotated examples for each feed.
- Multi-backend load balancing: a per-host backend pool with
  least-connections selection and health checking, wired into the request
  path (existing single `remote_host`/`remote_port` setups are
  unaffected).
- Response caching: cacheable upstream responses are now cached, with a
  cache key that includes scheme/host/port/method/path/query and
  `Accept-Encoding`, and a hard rejection of any response carrying
  `Set-Cookie` to prevent session-data leakage across requests.
- Cluster data-plane sync: admin rule/config edits on the main node now
  broadcast to workers and are consumed on the worker request path,
  letting a database-less worker enforce custom/IP/URL/sensitive rules
  purely from cluster sync.

### Changed

- Config defaults: OWASP CRS and GeoIP detection are now enabled out of
  the box (OWASP CRS at the lowest false-positive paranoia level, with
  graceful degradation when rule files are absent), and the default
  Admin API rate limit is more generous. CrowdSec and HTTP/3 now
  auto-enable when their required configuration is present, instead of
  needing a separate explicit switch.
- `MASTER_KEY` (encryption at rest) now requires at least 32 characters,
  raised from 16; the cluster CA passphrase keeps its existing 16-character
  minimum.
- Multi-node clusters now require a configured `join_token` — a join
  request without a valid token is rejected by the main node.
- Combining `cluster.crypto.auto_generate=true` with a non-empty `seeds`
  list is now a startup error instead of a silent hang (each node would
  otherwise mint its own untrusted CA and the cluster could never form).
- `trust_proxy_headers=true` with an empty `trusted_proxies` now refuses
  to start instead of only logging a warning.

### Fixed

- ACME certificate download could previously hang indefinitely on a
  slow/unresponsive CA; it now times out after 60 seconds and marks the
  certificate as errored.
- The rustls `ring` crypto provider is now installed explicitly at
  startup, fixing cluster mTLS and HTTP/3 failing to start in some
  deployments.

---

## [0.2.0] — 2026-03-27

### Security

- Eliminate 8 `panic!` calls in LazyLock regex initializers — replaced with
  `tracing::error!` + safe degradation (`RegexSet::empty()`) so a malformed
  compiled-in pattern never crashes the process.
- Add SSRF protection for Webhook and CrowdSec URLs with dual-mode validation
  (`url_validator.rs`): `validate_public_url()` resolves DNS and rejects RFC-1918
  / loopback / link-local / multicast addresses; `validate_scheme_only()` for
  contexts where DNS resolution is not yet available.
- Implement DNS rebinding guard using `resolve_to_addrs()` IP pinning — the
  resolved address set is cached and re-validated on each outbound connection to
  defeat time-of-check / time-of-use DNS rebinding attacks.
- Add iterative URL decoding (`url_decode_recursive`) to prevent double / triple
  encoding bypass of WAF rules (e.g., `%2527` → `%27` → `'`).
- Harden remote rule fetching: redirect following disabled, 30 s connect/read
  timeout enforced, response body capped at 10 MB.
- Add Admin API security middleware: IP allowlist enforcement, per-IP rate
  limiting, and strict security response headers (`X-Frame-Options`,
  `X-Content-Type-Options`, `Referrer-Policy`, `Content-Security-Policy`).
- Add login rate limiting (per-IP, configurable) and WebSocket upgrade IP
  allowlist to the Admin UI server.
- Fix cluster peer registration fencing: stale peer records are evicted before a
  new node with the same ID is accepted, preventing split-brain from rapid
  restart cycles.
- Fix XFF trusted-proxy CIDR validation: malformed CIDR strings in
  `trusted_proxies` now produce a config error at startup instead of a runtime
  panic.
- Fix rule deletion memory sync: rule removal now performs an atomic swap of the
  in-memory `RuleRegistry` so in-flight requests never observe a partially
  updated rule set.

### Added

- `detect_sqli` and `detect_xss` operators via the `libinjectionrs` pure-Rust
  crate — OWASP CRS core rules `CRS-942100` (SQL injection) and `CRS-941100`
  (XSS) are now fully evaluated at runtime instead of being silently skipped.
- Async `load_remote_sources()` method on `RuleRegistry` / `RemoteUrl` rule
  sources: remote rule sets are fetched in the background after startup so cold
  boot latency is unaffected.
- `url_validator` module (`waf-engine/src/security/url_validator.rs`) exposing
  `validate_public_url()` and `validate_scheme_only()`.
- `.cargo/audit.toml` policy file that suppresses known upstream transitive
  dependency advisories originating from the Pingora crate family (documented
  with justification comments).
- 116 new regression tests (suite total: 243) covering SSRF validation, encoding
  bypass, SQLi/XSS detection, cluster fencing, and dependency-upgrade
  compatibility.

### Changed

#### Dependency Upgrades

- **wasmtime**: 23.0.3 → 43.0.0 — resolves 5 published CVEs in the WASM
  runtime.
- **axum**: 0.7 → 0.8.8; **axum-extra**: 0.9 → 0.12 — aligns with the current
  stable axum ecosystem.
- **tower**: 0.4 → 0.5.3; **tower-http**: 0.5 → 0.6.8.
- **jsonwebtoken**: 9 → 10, switching to the `rust_crypto` backend to remove
  the OpenSSL dependency from the JWT path.
- **reqwest**: 0.12 → 0.13.
- **tokio-tungstenite**: 0.23 → 0.26.
- **toml**: 0.8 → 1.1.
- **serde_yaml**: deprecated 0.9 → **serde_yaml_ng** 0.10.
- **rustls-pemfile**: unmaintained crate replaced with the built-in PEM parser
  from **rustls-pki-types**.
- **sqlx**: set `default-features = false` to drop the unused `rsa` transitive
  dependency from the build graph.

### Fixed

- Remote URL rule sources were silently skipped in `load_all()` due to a missing
  async dispatch path — they are now loaded via `load_remote_sources()` after
  startup and on each scheduled refresh.
- OWASP CRS rules that use the `detect_sqli` / `detect_xss` operators were
  silently skipped because the operator was unregistered — the `libinjectionrs`
  integration now registers both operators at engine initialisation.
- Dead peer automatic eviction in cluster mode: peers that fail the phi-accrual
  threshold and do not reconnect within the configured grace period are now
  removed from the peer table and from the Admin UI node list.

---

## [0.1.0-rc.1] — 2026-03-16

### Added

#### Cluster — Full QUIC mTLS mesh (P1–P5 complete)

- **waf-cluster crate**: New crate implementing the full cluster protocol.

- **P1 — Transport & Certificates**
  - QUIC mTLS server/client (`transport/server.rs`, `transport/client.rs`) using
    quinn 0.11 + rustls 0.23 + rcgen 0.13 — reusing patterns from `gateway/http3.rs`.
  - Ed25519 cluster CA generation via `rcgen` (`crypto/ca.rs`).
  - Per-node certificate signing (`crypto/node_cert.rs`).
  - AES-GCM CA key storage for encrypted replication to workers (`crypto/store.rs`).
  - HMAC-SHA256 join token generation and validation (`crypto/token.rs`).
  - Length-prefixed JSON frame codec over QUIC streams (`transport/frame.rs`).
  - Static seed discovery from `ClusterConfig.seeds` (`discovery.rs`).
  - Heartbeat sender (periodic) and heartbeat tracker per peer (`health/`).

- **P2 — Rule & Config Sync**
  - `RuleChangelog` ring buffer (500-entry VecDeque) on main for incremental sync.
  - Full rule snapshot: serialize `RuleRegistry` → lz4-compressed JSON.
  - Incremental sync: workers send `RuleSyncRequest { current_version }` and receive
    only changed entries since their last known version.
  - Config sync protocol (TOML string) over a dedicated stream.
  - Attack event batching on workers with periodic flush to main.
  - `StorageMode` enum: `Full` (DB available) / `ForwardOnly` (writes forwarded).
  - `PendingForwards` for in-flight API write forwarding from workers to main.

- **P3 — Raft-lite Election & Failover**
  - `ElectionManager`: in-memory Raft-lite state machine (term, vote, timeout).
  - Phi-accrual failure detector (Cassandra-style) per-peer (`health/detector.rs`).
  - Role transitions: `Worker → Candidate → Main` and `Main → Worker`.
  - Split-brain prevention: fencing tokens + quorum requirement (N/2+1 votes).
  - CA key replication: encrypted CA key distributed to workers in `JoinResponse`.
  - CLI subcommands: `status`, `nodes`, `token generate`, `promote`, `demote`, `remove`.
  - 20 cluster tests across election, heartbeat, mTLS, and sync scenarios.

- **P4 — Admin UI Cluster Panel**
  - REST API under `/api/cluster/*` (5 endpoints: status, nodes, node detail,
    token generate, node remove).
  - `AppState.cluster_state: Option<Arc<NodeState>>` (None = standalone mode).
  - Four Vue 3 + Tailwind cluster views: Overview, Node Detail, Tokens, Sync Status.
  - i18n keys for English, Chinese, Russian, and Georgian.

- **P5 — Integration Test & Docker (this release)**
  - `docker-compose.cluster.yml`: 3-node cluster (1 main + 2 workers) using
    the existing `Dockerfile.prebuilt` pattern. Nodes communicate on port 16851
    via an internal `cluster_net` Docker network.
  - `tests/e2e-cluster.sh`: end-to-end test script verifying:
    - All 3 nodes healthy
    - Rule created on main syncs to workers within 15s
    - Election completes after stopping the main (new main elected)
    - Node rejoin after restart
  - `configs/cluster-node-{a,b,c}.toml`: per-node configuration files for the
    3-node docker-compose setup.
  - `docs/cluster-guide.md`: quick-start guide, full configuration reference,
    certificate management, troubleshooting, and architecture notes.
  - `cluster cert-init` CLI command: generates cluster CA + per-node certs
    offline for pre-provisioned deployments (`prx-waf cluster cert-init --nodes
    node-a,node-b,node-c --output-dir /certs`).
  - `ClusterCryptoConfig.ca_key` field: path to the CA private key file (main
    node only; empty on workers).
  - `CertificateAuthority::from_cert_pem()`: load CA cert without private key
    (used by worker nodes that only need to verify peer certs, not sign new ones).
  - Hostname resolution for cluster seeds: seeds can now be specified as
    `hostname:port` (e.g., `"node-a:16851"`) instead of requiring IP addresses —
    critical for docker-compose DNS names.
  - `auto_generate = false` path in `ClusterNode::run()`: loads certificates from
    files instead of always generating ephemeral in-memory certs.

### Changed

- `waf-common::config::ClusterCryptoConfig`: added `ca_key` field (empty default —
  fully backward-compatible with existing configs).
- `waf-cluster::crypto::ca::CertificateAuthority::as_rcgen_issuer()`: now returns
  an error if called on a cert-only instance (constructed via `from_cert_pem`).
- `waf-cluster::ClusterNode::run()`: restructured to support both in-memory cert
  generation (`auto_generate = true`) and file-based loading (`auto_generate = false`).
  NodeState is now created before cert setup to resolve `node_id` first.
- Cluster seed parsing: migrated from `str::parse::<SocketAddr>()` to
  `tokio::net::lookup_host()` for DNS/hostname support.

### Architecture Notes

- All cluster inter-node traffic runs over QUIC (UDP port 16851) with mutual TLS.
- Workers maintain an in-memory `RuleRegistry` populated via cluster sync.
  No SQLite required — workers operate database-free if needed.
- The entire cluster feature adds exactly **one new workspace dependency**: `lz4_flex`
  (all other deps — quinn, rustls, rcgen — were already in the workspace).
- WASM plugins are not synced to worker nodes in v1 (documented limitation).
- Standalone mode (no `[cluster]` section) continues to work with zero behavior change.

---

## [0.0.x] — Prior Releases

Phase 1–7 internal development milestones. Cluster P1–P4 completed 2026-03-16.
