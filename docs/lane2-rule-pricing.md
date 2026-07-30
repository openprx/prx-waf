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

## Batch 1 — the fifteen cases §4 calls recoverable

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

Measured in the same sweep, same baseline. **Twenty-four of the twenty-seven
recover nothing at all.**

### The three that recover something

| rule_key | family | conf | det +N | FP +M | blocked +K | FPblk | touched | verdict |
|---|---|---|---|---|---|---|---|---|
| `sql.stacked` | `sql_injection` | 90 | +1 | +2 | **+1** | 0 | 2 | worth on, threshold/scope first |
| `rce.backtick_cmd` | `rce` | 78 | +1 | +3 | 0 | 0 | 5 | keep off |
| `xpath.bare_logical` | `xpath_injection` | 20 | +1 | 0 | 0 | 0 | 21 | keep off |

**`sql.stacked` is the only rule in all thirty-eight that changes a blocking
decision**, and it does it by corroboration rather than on its own. `sqli-003`
was already detected at score 45 by `ast.comment_obfusc` + `ast.stacked`;
`sql.stacked` at confidence 90 and the family's 0.5 detector weight takes the
same request to 90, over `block_threshold`, and it becomes the 76th block. Its
own new detection, `sqli-019`, scores 45 and does not block. Its cost is two
`fp-log` at 45: `content-043`, a SQL migration file uploaded to a repository
browser, and `content-047`, a MySQL slow-query log pasted into an issue thread —
both stacked SQL, because that is what a migration file and a query log are.
Attack and false positive score identically again, so no `log_threshold` move
separates them without also dropping `sqli-019`, and `sql_injection` runs
`log_threshold = 30` deliberately (the `configs/default.toml` comment explains
why) so raising it has a cost this sweep did not measure. The verdict is that
this rule is worth having and should not be switched on by itself.

**`rce.backtick_cmd` is the cleanest demonstration of deferred cost turning
real.** Four corpus rows sat at score 39 against `log_threshold = 40`, one
point short, held there by the already-on `rce_ast.cmd_subst`. Enabling
`rce.backtick_cmd` corroborates all four to 78. One is the attack `rce-005` —
it fixes the single `sub-threshold` attack in the whole baseline. The other
three are `content-030` (an operations runbook), `content-038` (a bug report
whose repro is `curl … | jq`) and `content-040` (a code-review comment about
shell command substitution). One attack for three false positives, from a
threshold nobody moved.

**`xpath.bare_logical`'s `+1` is bookkeeping, not detection.** `xpath-007` was
already producing a security event at score 40, in the `wrong-family` bucket,
won by `ast.tautology`. The rule adds an XPath signal to the same request at the
same score, which moves it to `misattributed` — a bucket this harness counts as
detected. An operator's event log is unchanged. For that, the rule fires on 21
benign rows.

### The eleven that recover nothing and fire on benign traffic anyway

Zero attacks, zero false positives *today*, and a standing contact with benign
traffic that the FP column cannot see:

| rule_key | conf | benign rows touched | highest benign score reached |
|---|---|---|---|
| `xpath.bare_double_slash` | 25 | **94 of 220** | 88 |
| `ldap.bare_logical` | 20 | **71** | 78 |
| `xpath.bare_predicate` | 15 | **45** | 88 |
| `ldap.bare_wildcard` | 20 | 17 | 88 |
| `rce_ast.cmd_subst_any` | 50 | 14 | 78 |
| `ssti.jinja_delim` | 30 | 11 | 30 |
| `ssti.dollar_delim` | 25 | 6 | 39 |
| `xpath.bare_func` | 20 | 3 | 20 |
| `rce.cmd_sep_common` | 45 | 2 | 23 |
| `sql.hex_const` | 40 | 2 | 20 |
| `ldap.paren_adjacency` | 25 | 1 | 25 |

`xpath.bare_double_slash` takes the benign `sub-threshold` bucket from 3 rows to
94 — **42% of the benign corpus starts carrying a score** — and detects not one
attack. `ldap.bare_logical` does the same to 68 rows. These are the rules the
`default_on = false` literal was protecting against, and the measurement is
unambiguous: on this corpus they are pure noise with no upside whatsoever.

Every one of them is safe today only because it sits under a threshold. A weight
change, a `log_threshold` change, or one more rule firing on the same field
turns any of these columns into false positives — which is exactly what
`rce.backtick_cmd` does to four rows one point below the line.

### The two that recover nothing and flag benign traffic

| rule_key | family | conf | det | FP | flagged |
|---|---|---|---|---|---|
| `sql.info_schema` | `sql_injection` | 65 | 0 | **+1** | `content-046` — internal docs teaching analysts to introspect the warehouse via `information_schema` |
| `xxe.param_entity_ref` | `xxe` | 55 | 0 | **+1** | `content-048` — a desktop crash report carrying the ORM's parameterised SQL debug log |

Cost with no benefit at all on this corpus. Keep off.

### The eleven that do nothing whatsoever

`deser.dotnet_formatter_name`, `deser.java_pkg_generic`, `deser.php_array`,
`deser.py_reduce`, `ldap.filter_break_any_attr`, `ldap.filter_group`,
`rce.mkfifo_revshell`, `sql.chr_freq`, `ssti.getclass`, `ssti.hash_delim`,
`ssti.py_class`.

No attack recovered, no benign row flagged, no benign row touched. **This is not
evidence that they are safe to enable** — it is evidence that this corpus
contains nothing they match, in either direction, and the corpus is 390 rows.
For these eleven the measurement's answer is "no information", and that is a
different answer from "no cost".

---

## The set that is worth shipping on

Seven rules, all from batch 1, recover eleven attacks between them and touch not
one benign row:

```toml
[content_security]
rules_enabled = [
  "nosql.comparison_operator",
  "nosql.regex_operator",
  "nosql.logical_operator",
  "nosql.expr_operator",
  "deser.php_object_injection",
  "traversal.sensitive_abs_ops",
  "xxe.entity_expansion",
]
```

**Measured as a set, not added up.** The combination was run as its own
experiment (`COMBO=free7:…`), because a sum would not be trustworthy after what
`sql.stacked` and `rce.backtick_cmd` did with corroboration:

| | shadow detected | shadow FP | shadow FP-block | enforce blocked | enforce FP-block |
|---|---|---|---|---|---|
| baseline | 128 (75.29%) | 10 | 2 | 75 | 2 |
| seven rules on | **139 (81.76%)** | **10** | **2** | **75** | **2** |

`+11` detected, and every other column identical — the set is exactly the union
of its parts, with no interaction in either direction. Attack rows recovered:
`nosql-001` `nosql-003` `nosql-004` `nosql-005` `nosql-006` `nosql-007`
`nosql-011` `trav-005` `xxe-005` `deser-006` `deser-015`.

Family effect: `nosql_injection` 40.0% → 86.7%, and `README.md`'s claim that
its low rate is a configuration choice rather than a capability gap is now
measured rather than asserted.

Nothing in this section changes any `default_on`. It is what the numbers
support; the decision is not this document's.

---

## The whole sweep in one paragraph

Thirty-eight rules, 39 corpus replays in each of two modes. Fourteen rules
recover at least one attack; twenty-four recover none. Seven are free and
recover eleven cases. Eight cost false positives. Eleven fire on benign traffic
while recovering nothing, one of them on 42% of the benign corpus. Eleven do
nothing at all and are therefore unmeasured rather than safe. **Not one rule of
the thirty-eight produced a blocking false positive**, so `fp_block` stays at 2
throughout and no rule in this set is an obstacle to `rollout_bps` — and **only
one rule of the thirty-eight, `sql.stacked`, improves the blocking decision at
all**. Enabling default-off rules is a detection-quality lever and almost not a
blocking lever.

---

## What this document does not establish

* **Exactly one combination was measured.** Every other number is one rule
  against the baseline, and rows must not be added up: `sql.stacked` produced a
  block by corroborating with two rules already on, and `rce.backtick_cmd`
  produced three false positives by corroborating four rows from 39 to 78. Any
  set proposed for shipping needs its own run (`COMBO=` in `price-rules.sh`);
  the seven-rule set above has one and no other set does.
* **No `default_on` was changed.** This is a price list. Which rules ship on is
  a decision the price list informs and does not make.
* **220 benign rows are not a holdout.** They are a corpus of shapes this
  product has been burned by, which makes a false positive in it strong evidence
  and makes zero false positives in it weak evidence. `touched = 0` is the
  better reading of "found nothing to fire on" and it is still 220 requests, not
  a traffic sample. For the eleven rules that moved no column at all it is the
  whole of what is known about them.
* **No threshold, weight or scope change was measured.** Several verdicts above
  say a rule would be worth having under a different threshold or on a narrower
  route. None of those alternatives was run; each carries its own cost to the
  detections the current setting is buying.
* **The corpus carries no binary bodies** (`tests/lane2/README.md`), so any rule
  whose shape lives in non-UTF-8 bytes is under-measured here by construction.
* **Detector weights were not varied.** Every number is at the shipped weights,
  so a rule in a 0.5-weight family is priced at half its confidence and would
  read differently in a family scored at 1.0.
