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
