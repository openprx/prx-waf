# What the default-off Lane 2 rules cost

Thirty-eight of Lane 2's rules ship disabled. `docs/lane2-blind-spots.md` §4
says fifteen corpus attacks are "recoverable by enabling an existing rule" and
§6 says, in as many words, that the fifteen are **arithmetic and not
measurement** — confidence × weight compared against a threshold, with the
pattern checked by eye. There was no per-rule config key to flip, so nothing was
flipped.

`v0.2.175` added `[content_security] rules_enabled` / `rules_disabled`. This
document is the measurement that replaces the arithmetic.

## How to reproduce

```bash
tests/lane2/price-rules.sh                          # all 38, one at a time
tests/lane2/price-rules.sh nosql.expr_operator      # or just some
python3 tests/lane2/price-rules.py --dir "$WORK/pricing"
```

Each rule gets the whole 390-row corpus in **both modes** with that one rule on
and nothing else changed. The delta against a baseline run in the same sweep is
that rule's bill. One rule per run is not a convenience: thirty-eight rules on
at once produce a single mixed number, and a benign request flagged by their
union names no rule to leave off.

**The baseline run reproduces `tests/lane2/baseline.json` exactly** — shadow
128 detected / 10 false positives / 2 blocking false positives, enforce 75
blocked / 2 / 2. Every delta below is read against those numbers.

## How to read the columns

| column | meaning |
|---|---|
| **det** | shadow: attack rows that moved into `detected` or `misattributed` |
| **FP** | shadow: benign rows that moved into `fp-log` or `fp-block` |
| **blocked** | enforce: attack rows that moved into `blocked` |
| **FPblk** | enforce: benign rows that moved into `fp-block`. **This is the column that gates `rollout_bps`** |
| **touched** | benign rows on which the rule fired *at all*, whatever bucket they landed in |

`touched` is the widest column and the one that decides a close call. A bucket
only changes when a row crosses a threshold, so the FP column cannot see a rule
that fires on twenty benign rows and pushes none of them over — and that rule
will produce false positives the moment a threshold, a weight or a corroborating
rule moves. A rule with a large `touched` and a zero `FP` has not been shown to
be safe; it has been shown to be one change away.

---

## Batch 1 — the fifteen §4 calls recoverable

Eleven rules cover the fifteen cases `docs/lane2-blind-spots.md` §5 item 1
names. They are measured first because they are the source of the arithmetic
this document exists to check.

| rule_key | family | conf | det +N | FP +M | blocked +K | FPblk | touched | verdict |
|---|---|---|---|---|---|---|---|---|
| `nosql.comparison_operator` | `nosql_injection` | 55 | **+3** | 0 | 0 | 0 | 0 | **default on** |
| `nosql.regex_operator` | `nosql_injection` | 60 | **+2** | 0 | 0 | 0 | 0 | **default on** |
| `nosql.logical_operator` | `nosql_injection` | 45 | **+2** | 0 | 0 | 0 | 0 | **default on** |
| `nosql.expr_operator` | `nosql_injection` | 75 | **+1** | 0 | 0 | 0 | 0 | **default on** |
| `deser.php_object_injection` | `deserialization` | 60 | **+2** | 0 | 0 | 0 | 0 | **default on** |
| `traversal.sensitive_abs_ops` | `traversal` | 55 | **+1** | 0 | 0 | 0 | 0 | **default on** |
| `xxe.entity_expansion` | `xxe` | 65 (×3) | **+1** | 0 | 0 | 0 | 0 | **default on** |
| `traversal.plain_dotdot` | `traversal` | 50 | +2 | **+2** | 0 | 0 | 2 | keep off |
| `ssti.jinja_arith_probe` | `ssti` | 45 | +1 | **+1** | 0 | 0 | 1 | keep off |
| `ssti.template_directive` | `ssti` | 45 | +1 | **+1** | 0 | 0 | 1 | keep off |
| `xxe.doctype_external` | `xxe` | 60 | +1 | **+1** | 0 | 0 | 1 | keep off |

Which rows moved:

| rule | attacks recovered | benign flagged |
|---|---|---|
| `nosql.comparison_operator` | `nosql-001` `nosql-004` `nosql-006` | — |
| `nosql.regex_operator` | `nosql-003` `nosql-011` | — |
| `nosql.logical_operator` | `nosql-005` `nosql-006` | — |
| `nosql.expr_operator` | `nosql-007` | — |
| `deser.php_object_injection` | `deser-006` `deser-015` | — |
| `traversal.sensitive_abs_ops` | `trav-005` | — |
| `xxe.entity_expansion` | `xxe-005` | — |
| `traversal.plain_dotdot` | `trav-005` `trav-016` | `content-064` `content-109` |
| `ssti.jinja_arith_probe` | `ssti-001` | `content-026` |
| `ssti.template_directive` | `ssti-006` | `content-025` |
| `xxe.doctype_external` | `xxe-004` | `content-003` |

### The arithmetic was right about the attack half and silent about the rest

All fifteen are recovered. `nosql-001/003/004/005/006/007/011`, `ssti-001`,
`ssti-006`, `trav-005`, `trav-016`, `xxe-004`, `xxe-005`, `deser-006`,
`deser-015` — every case §5 item 1 lists, and no case it does not. The
confidence-times-weight prediction held on all fifteen. That is the part of §4
this measurement confirms.

Two things it did not say:

**Eleven of the fifteen are free; the other four cost five false positives.**
The seven zero-cost rules recover eleven cases between them and flag nothing.
The remaining four cases — `ssti-001`, `ssti-006`, `trav-016`, `xxe-004` — cost
`content-003`, `-025`, `-026`, `-064`, `-109`. Taking all fifteen moves the
benign false-positive column from 10 to 15, **4.55% → 6.82%**, a 50% increase in
the FP rate to buy 4 detections. Taking only the eleven free ones moves shadow
detection 128 → 139 (75.29% → 81.76%) and moves the FP column not at all.

**None of the fifteen changes what gets blocked.** Every recovered attack scores
its rule's confidence — 45, 50, 55, 60, 65 or 75 — against a
`block_threshold` of 80, and every one of them stays `not-blocked` in enforce
mode. The enforce column is `+0` for all eleven rules, on both halves. The
fifteen are a detection-quality gain and nothing else; the enforce numbers
75/2/2 are untouched by every rule in this batch.

### Why none of the four costly rules is a threshold problem

The obvious next move for a rule that recovers one attack and flags one benign
request is to raise its family's `log_threshold` until the benign row drops out.
It does not work here, and the reason is visible in the scores:

| rule | attack score | benign score |
|---|---|---|
| `ssti.jinja_arith_probe` | `ssti-001` = 45 | `content-026` = 45 |
| `ssti.template_directive` | `ssti-006` = 45 | `content-025` = 45 |
| `xxe.doctype_external` | `xxe-004` = 60 | `content-003` = 60 |
| `traversal.plain_dotdot` | `trav-005` `trav-016` = 50 | `content-064` `content-109` = 50 |

**The attack and the false positive score identically, in all four.** Nothing
else fires on these rows, so the request score *is* the rule's confidence, and a
threshold that drops the benign row drops the attack with it. There is no
per-rule threshold to tune and no separation to find. Whatever fixes these is a
narrower pattern or a route scope (`enforcement_overrides`, or not running the
rule on the route that legitimately carries the shape) — never a number.

That is also why the "worth enabling once a threshold is fixed" verdict is
**empty for this batch**. Every rule here is either free or unseparable.

### What the four cost, named

The benign rows are not marginal or exotic. Each is a shape this repository has
already been burned by, which is why it is in the corpus:

* `content-003` — `xhtml-doctype-richtext`. An email-builder draft whose HTML
  carries the standard XHTML transitional doctype. `xxe.doctype_external` fires
  on the `PUBLIC` doctype. This is the exact false positive the
  `[content_security.attacks.xxe]` comment in `configs/default.toml` predicts as
  the reason the rule ships off — the prediction was correct and is now measured.
* `content-025` — `freemarker-fragment`. A Freemarker template file uploaded
  into a Java project's resources directory. `ssti.template_directive` matches
  the `#set(` directive, which is what a template file is made of.
* `content-026` — `ssti-docs`. A defensive security article that names the
  canonical `{{7*7}}` probe while explaining the mitigation. `ssti-001` *is*
  `{{7*7}}`, so the rule cannot tell the attack from the article about the
  attack.
* `content-064` — `journalctl-excerpt`. A customer attaching a journalctl
  excerpt to a support ticket; the log text contains `../`.
* `content-109` — `relative-path-in-content`. An asset-reference editor storing
  relative paths that the site builder resolves inside the tenant root. `../`
  is the feature.

`traversal.plain_dotdot` is the worst bargain of the four and worth separating
out: `trav-005`, one of the two attacks it recovers, is **already recovered for
free** by `traversal.sensitive_abs_ops`. Its unique contribution is `trav-016`
alone — one attack, for two false positives.

---

## Batch 2 — the other 27 rules

**Not yet measured.** The sweep runs them in the order below and this section
will be filled in as the runs land. No number in it should be assumed until it
is written down here.

`sql.stacked`, `sql.info_schema`, `sql.chr_freq`, `sql.hex_const`,
`rce.mkfifo_revshell`, `rce.cmd_sep_common`, `rce.backtick_cmd`,
`rce_ast.cmd_subst_any`, `xxe.param_entity_ref`, `ssti.getclass`,
`ssti.py_class`, `ssti.jinja_delim`, `ssti.dollar_delim`, `ssti.hash_delim`,
`ldap.filter_break_any_attr`, `ldap.filter_group`, `ldap.paren_adjacency`,
`ldap.bare_wildcard`, `ldap.bare_logical`, `xpath.bare_double_slash`,
`xpath.bare_logical`, `xpath.bare_predicate`, `xpath.bare_func`,
`deser.dotnet_formatter_name`, `deser.php_array`, `deser.py_reduce`,
`deser.java_pkg_generic`.

---

## What this document does not establish

* **Nothing here is a combination.** Every number is one rule against the
  baseline. Several rules can corroborate on one request — that is how
  `block_threshold = 80` is reached in the two-detector families — so the cost
  of enabling a set is **not** the sum of its rows, in either column. A set worth
  shipping should be measured as a set (`COMBO=` in `price-rules.sh`).
* **No `default_on` was changed.** This is a price list. Which rules ship on is
  a decision the price list informs and does not make.
* **220 benign rows are not a holdout.** They are a corpus of shapes this
  product has been burned by, which makes a false positive in it strong evidence
  and makes zero false positives in it weak evidence. `touched = 0` is the
  better reading of "found nothing to fire on" and it is still 220 requests, not
  a traffic sample.
* **The corpus carries no binary bodies** (`tests/lane2/README.md`), so any rule
  whose shape lives in non-UTF-8 bytes is under-measured here by construction.
