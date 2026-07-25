# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Version numbers follow [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

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
