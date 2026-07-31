# What the Lane 2 rules cost

Started as the bill for the rules that ship disabled, and grew the two sections
at the end as the switchable surface did.

Thirty-eight of Lane 2's rules ship disabled. `docs/lane2-blind-spots.md` §4
says fifteen corpus attacks are "recoverable by enabling an existing rule" and
§6 says, in as many words, that the fifteen are **arithmetic and not
measurement** — confidence × weight compared against a threshold, with the
pattern checked by eye. There was no per-rule config key to flip, so nothing was
flipped.

`v0.2.175` added `[content_security] rules_enabled` / `rules_disabled`. This
document is the measurement that replaces the arithmetic.

The same sweep pointed the other way — one default-**on** rule taken away per
run — prices the sixty-six rules that were already running, and is in
[`docs/lane2-latent-pressure.md`](lane2-latent-pressure.md). Read the two
together: this one says what the off rules would cost, that one says what the on
rules are costing.

> **Two things happened after the sweep below, and both are priced further
> down.** `v0.2.188` turned seven of the thirty-eight on, which moved the
> baseline every price here was read against from shadow 128 to shadow **139**.
> `v0.2.192` put the eighteen rules that decide in code on the switchable
> surface, so the inventory is **115 keys, 81 on and 34 off** rather than 97/66/31
> and eighteen rules that had never been measured could be. The two sections that
> answer for them are
> [the eighteen that decide in code](#the-eighteen-rules-that-decide-in-code)
> and [what the seven flips did to the other thirty-one prices](#what-the-seven-flips-did-to-the-other-thirty-one-prices).

## How to reproduce

```bash
tests/lane2/price-rules.sh                          # all 34 default-off, one at a time
tests/lane2/price-rules.sh nosql.expr_operator      # or just some
DIRECTION=disable tests/lane2/price-rules.sh        # or all 81 default-on
python3 tests/lane2/price-rules.py --dir "$WORK/pricing"
```

Each rule gets the whole 390-row corpus in **both modes** with that one rule on
and nothing else changed. The delta against a baseline run in the same sweep is
that rule's bill. One rule per run is not a convenience: thirty-eight rules on
at once produce a single mixed number, and a benign request flagged by their
union names no rule to leave off.

**The baseline run reproduces `tests/lane2/baseline.json` exactly** — shadow
128 detected / 10 false positives / 2 blocking false positives, enforce 75
blocked / 2 / 2. Every delta below is read against those numbers, which are the
`v0.2.181` baseline and **not** the shipped one: `baseline.json` records shadow
139 since `v0.2.188`. The later sections state their own baseline.

**Recorded from `9df9c045` (`v0.2.181`)**, release build, `configs/default.toml`
unmodified except for the one `rules_enabled` line each run substitutes, 2×39
corpus replays plus one combination. `baseline.json`, the corpus and every
rule's `default_on` are untouched by this work: the sweep points `SRC` at a
symlink mirror of the tree whose only real directory is `configs/`.

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
| `traversal.plain_dotdot` | `traversal` | 50 | +2 → **+1** | **+2** | 0 | 0 | 2 | keep off |
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
| `traversal.plain_dotdot` | `trav-005` `trav-016` (`trav-005` no longer — see [below](#the-one-price-that-moved)) | `content-064` `content-109` |
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
94 — **91 benign rows, 41% of the corpus, start carrying a score** — and detects
not one attack. `ldap.bare_logical` does the same to 68 rows. These are the rules the
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

## The set that is worth shipping on — and now ships on

Seven rules, all from batch 1, recover eleven attacks between them and touch not
one benign row:

* `nosql.comparison_operator`
* `nosql.regex_operator`
* `nosql.logical_operator`
* `nosql.expr_operator`
* `deser.php_object_injection`
* `traversal.sensitive_abs_ops`
* `xxe.entity_expansion`

**`v0.2.187` flipped all seven `default_on` to `true`**, so this is the shipped
posture and no config is needed to get it. An operator who disagrees with any of
them takes it back out by key:

```toml
[content_security]
rules_disabled = ["traversal.sensitive_abs_ops"]
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

### What the flip did that the sweep could not measure

The sweep enabled rules through `rules_enabled`, which is a **runtime**
amendment. `default_on` is **compiled in**, and one thing reads it directly:
`detectors::default_on_rce_traversal_patterns`, the single source of truth
behind `NORMALISED_STRONG_STRUCTURE` — the gate that decides whether a
shell-normalised or blind base64/hex view is worth emitting at all. Flipping
`traversal.sensitive_abs_ops` therefore widens that gate, so a payload that
*decodes* to `/etc/hosts` or `/proc/self` now earns a synthetic view where it
previously did not. That is the gate's stated invariant working as designed — it
must never reject a structure a default-on detector would accept — but it is a
behaviour change the `rules_enabled` runs could not have produced.

So the flip was re-measured rather than inferred, and the widening moved nothing
on this corpus: `trav-020` picked up a second traversal rule at an unchanged
score of 75, no benign row gained a signal, and `tests/lane2/baseline.json`
records shadow 139 / 10 / 2 and enforce 75 / 2 / 2 — the combination row above,
reproduced from the shipped posture with both rule lists empty.

---

## The whole sweep in one paragraph

Thirty-eight rules, 39 corpus replays in each of two modes. Fourteen rules
recover at least one attack; twenty-four recover none. Seven are free and
recover eleven cases. Eight cost false positives. Eleven fire on benign traffic
while recovering nothing, one of them on 94 of the 220 benign rows. Eleven do
nothing at all and are therefore unmeasured rather than safe. **Not one rule of
the thirty-eight produced a blocking false positive**, so `fp_block` stays at 2
throughout and no rule in this set is an obstacle to `rollout_bps` — and **only
one rule of the thirty-eight, `sql.stacked`, improves the blocking decision at
all**. Enabling default-off rules is a detection-quality lever and almost not a
blocking lever.

---

# The eighteen rules that decide in code

Everything above is about rules that are a row in a regex table. Eighteen more
are not: the five SQL-AST structures, the nine XSS DOM constructs, the two XSS
JS token classes and the two pickle opcode grades decide from *parsed structure*,
so there was no pattern to leave out of a compile step and no key
`rules_enabled` would accept. `v0.2.192` gave them one. This is their price, and
it is the first time any of them has had one.

**Recorded from `c5b507f1` (`v0.2.192`)**, release build, ports `184xx`,
Postgres on `15808`. This section and
[the one after it](#what-the-seven-flips-did-to-the-other-thirty-one-prices)
share one measurement: 17 disable-direction runs (baseline, fifteen rules, one
combination) and 12 enable-direction runs (baseline, four rules, seven
combinations) in both modes, plus one shadow-only run that switches a rule off
and three on at once, which `price-rules.sh` cannot express. The baseline run
in both directions reproduces `tests/lane2/baseline.json` exactly — shadow
**139 / 10 / 2**, enforce **75 / 2 / 2** — and every number below is read
against it. `configs/default.toml`, the corpus, `baseline.json` and every rule's
`default_on` are untouched: the sweep points `SRC` at a symlink mirror whose only
real directory is `configs/`.

Fifteen of the eighteen ship **on**, so they are priced the way
[`lane2-latent-pressure.md`](lane2-latent-pressure.md) prices a running rule —
taken away one at a time, `DIRECTION=disable`, every column reading as what the
rule does when it is on. Three ship **off** and are priced by the enable sweep
like any other default-off rule.

## The fifteen that ship on

| rule_key | family | detector | conf | det | FP | blocked | FPblk | touched | attack rows it fires on |
|---|---|---|--:|--:|--:|--:|--:|--:|--:|
| `xss.script_tag` | `xss` | `xss_dom` | 90 | **+8** | **+2** | +0 | 0 | **3** | 8 |
| `xss.event_handler` | `xss` | `xss_dom` | 85 | **+4** | **+1** | +1 | 0 | **1** | 5 |
| `ast.tautology` | `sql_injection` | `ast` | 80 | +3 | 0 | +0 | 0 | 0 | 9 |
| `ast.stacked` | `sql_injection` | `ast` | 90 | +1 | 0 | +1 | 0 | 0 | 2 |
| `ast.subquery` | `sql_injection` | `ast` | 78 | +1 | 0 | +0 | 0 | 0 | 1 |
| `xss.svg_onload` | `xss` | `xss_dom` | 88 | +1 | 0 | +2 | 0 | 0 | 3 |
| `xss.iframe_srcdoc` | `xss` | `xss_dom` | 85 | +1 | 0 | +0 | 0 | 0 | 1 |
| `xss.js_url` | `xss` | `xss_dom` | 85 | +1 | 0 | +0 | 0 | 0 | 1 |
| `ast.union` | `sql_injection` | `ast` | 85 | +0 | 0 | +2 | 0 | 0 | 4 |
| `ast.dangerous_fn` | `sql_injection` | `ast` | 85 | +0 | 0 | +2 | 0 | 0 | 3 |
| `xss.js_exfil` | `xss` | `xss_js` | 88 | +0 | 0 | +2 | 0 | 0 | 2 |
| `xss.js_sink` | `xss` | `xss_js` | 85 | +0 | 0 | +1 | 0 | 0 | 1 |
| `deser.py_pickle_reduce_exec` | `deserialization` | `deser_struct` | 92 | +0 | 0 | +0 | 0 | 0 | 2 |
| `xss.data_html_url` | `xss` | `xss_dom` | 82 | +0 | 0 | +0 | 0 | 0 | **0** |
| `deser.py_pickle_dangerous_global` | `deserialization` | `deser_struct` | 85 | +0 | 0 | +0 | 0 | 0 | **0** |

Which rows move when the rule is taken away:

| rule | detections it is carrying | blocks it is carrying | benign rows it fires on |
|---|---|---|---|
| `xss.script_tag` | `xss-001` `xss-006` `xss-009` `xss-010` `xss-011` `xss-014` `xss-017` `xss-019` | — | `content-005` `content-010` (both false positives) + `content-059` |
| `xss.event_handler` | `xss-002` `xss-008` `xss-012` `xss-020` | `xss-013` | `content-011` (a false positive) |
| `ast.tautology` | `sqli-001` `sqli-005` `sqli-018` | — | — |
| `ast.stacked` | `sqli-003` | `sqli-010` | — |
| `ast.subquery` | `sqli-012` | — | — |
| `ast.union` | — | `sqli-014` `sqli-015` | — |
| `ast.dangerous_fn` | — | `sqli-004` `sqli-006` | — |
| `xss.svg_onload` | `xss-003` | `xss-016` `xss-018` | — |
| `xss.iframe_srcdoc` | `xss-005` | — | — |
| `xss.js_url` | `xss-007` | — | — |
| `xss.js_exfil` | — | `xss-016` `xss-018` | — |
| `xss.js_sink` | — | `xss-013` | — |
| `deser.py_pickle_reduce_exec` | — | — | — |

### `xss.script_tag` is the most expensive rule in Lane 2, and the most valuable

It is the only rule anywhere in the inventory that carries eight detections and
two false positives at once. Both readings are true and neither is the whole
story:

* **Take it away and two of the ten false positives go.** `content-005` is a
  knowledge-base article about output escaping that quotes
  `&lt;script&gt;alert(1)&lt;/script&gt;` inside a `<code>` block; `content-010`
  is a single-page-app shell saved by a site template editor, whose
  `<script src="assets/main.js" defer>` is the application. Both score 45 — the
  DOM detector alone at weight 0.5 — and both go to `clean`.
* **The same removal costs eight real XSS detections**, a quarter of the whole
  XSS family's shadow number, and takes shadow detection from 139 to 131.

There is no threshold between them: 45 is the score on the attack rows and 45
is the score on the two benign rows, for the same reason the SSTI probe rules
have no threshold — a `<script>` element in a stored HTML field is the same
parse whether the field is an attack or a page template.

It also fires on `content-059` without being the reason that row is a false
positive; the log-shipper row is carried to 68 by `sql.union_null` and
`traversal.sensitive_abs` and stays there when the XSS signal goes.

### The two XSS DOM rules that produce false positives, taken away together

Three of the ten false positives come from `xss.script_tag` and
`xss.event_handler`. That makes "switch off the two noisy DOM constructs" an
obvious operator move, and it is worth having the number rather than the
adjective. Measured as its own run (`COMBO=xssdomfp:…`) rather than summed:

| | shadow detected | shadow FP | shadow FP-block | enforce blocked | enforce FP-block |
|---|---|---|---|---|---|
| shipped | 139 (81.76%) | 10 | 2 | 75 | 2 |
| both off | **127 (74.71%)** | **7** | 2 | **74** | 2 |

**Twelve detections and one block, for three false positives.** This combination
*is* the sum of its parts — 8 + 4 detections, 2 + 1 false positives, 0 + 1
blocks, no interaction in either direction — which is worth stating because
`sql.stacked` and `rce.backtick_cmd` are the standing proof that a combination
need not be. The trade is 4.55% → 3.18% on the benign half against 81.76% →
74.71% on the attack half, and the blocking false-positive column does not move
because neither rule was ever behind one.

### The AST rules block more than they detect, and that is the design

Five rules, five detections and five blocks between them, on ten distinct rows.
`sqlparser-rs` runs at weight 0.5 in a two-detector family, so an AST structure
on its own scores 39 to 45 and mostly rides along with the regex rule that
already logged the row — which is why `ast.union` and `ast.dangerous_fn` carry
no detection at all and still carry two blocks each. **For those two the blocks
are the whole of their value**: they are the corroborating half of
`0.5·c_struct + 0.5·c_ast ≥ 80`, and without one of the five, `sqli-004`
`sqli-006` `sqli-010` `sqli-014` `sqli-015` are logged and not blocked. Read
against `docs/lane2-blind-spots.md`, this is the measured version of "the AST
layer is doing real work": **five of the seventy-five blocks in the whole
corpus, one in fifteen, need one of these five rules to exist**, and no other
family's blocks depend on a single detector this way.

`ast.tautology` is the exception in the other direction — three detections, no
blocks, and contact with **nine** attack rows, six of which are XPath. A quote
tautology is a quote tautology whichever grammar it was aimed at, and on those
six rows the XPath family scores higher and wins the roll-up, so the SQL signal
is present and invisible. That is the same bookkeeping effect
`xpath.bare_logical` produces from the other side.

### Two rules fire on nothing at all, for two different reasons

`xss.data_html_url` (conf 82) and `deser.py_pickle_dangerous_global` (conf 85)
produce **no signal on any of the 390 rows**, in either direction, in either
mode. They are the only two of the eighteen that do, and the corpus is not
silent about the shapes they are for:

* **`xss.data_html_url` has a corpus row and still does not fire.** `xss-010` is
  `url=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==` and is
  detected — by `xss.script_tag`, on the base64-decoded view, because the rule
  wants a `data:text/html` URL **in a real URL attribute of parsed HTML** and
  `xss-010` puts it in a query parameter. The gap is the delivery shape, not the
  scheme classifier. A row that stores `<a href="data:text/html,…">` in a rich
  text field would price it; the corpus has no such row.
* **`deser.py_pickle_dangerous_global` has never been observed firing**, and
  putting it where the sweep could price it was the stated reason it entered the
  inventory. The sweep now says the same thing the code comment said, with a
  measurement behind it: the grade below the one that fires carries nothing on
  this corpus. That is **no information, not a clean bill** — the 220 benign
  rows contain no pickle at all, so this measurement cannot distinguish "the
  stack model never declines to model a reduction" from "the corpus never asked
  it to".

`deser.py_pickle_reduce_exec` is a third kind of zero and should not be read as
the other two. It **does** fire — `deser-007` and `deser-009`, at confidence 92,
the strongest signal on either row — and taking it away costs nothing, because
`deser.java_serial_b64` and the rest of the regex table already carry both rows
over `block_threshold`. The opcode walker is redundant on this corpus rather
than idle on it, which is a much better place for a parser to be than the
reverse.

## The three that ship off

`xss.object_embed`, `xss.base_href` and `xss.dangling_open_tag` were reachable
only from a `#[cfg(test)]` constructor until `v0.2.192`. This is the first time
they have run against real corpus rows.

| rule_key | conf | det +N | FP +M | blocked +K | FPblk | touched | verdict |
|---|--:|--:|--:|--:|--:|--:|---|
| `xss.object_embed` | 80 | +0 | **+1** | 0 | 0 | 1 | **keep off** — cost with no benefit |
| `xss.base_href` | 80 | +0 | +0 | 0 | 0 | **0** | masked, not free — see below |
| `xss.dangling_open_tag` | 50 | +0 | +0 | 0 | 0 | 1 | no detection, one benign row under the line |

**`xss.object_embed` costs exactly what the code comment predicted.** The
`FP-4` note on the constant says legitimate PDF and media embeds hit it 3/3 in a
fire drill; the corpus has one such row and it hits it 1/1. `content-009` is a
CMS page embedding a hosted safety data sheet —
`<object data="…/4471.pdf" type="application/pdf"><embed src="…" /></object>` —
and it scores 40 against `xss.log_threshold = 40`, landing exactly on the line
as a new `fp-log`. It recovers no attack. On this corpus the rule is pure cost
and the eleventh false positive.

**`xss.base_href`'s zero is masking, not absence, and the corpus proves it.**
The rule fires on nothing in the shipped posture, but `content-010` *is* the
`base-href` trap: `<base href="/app/">` in a saved SPA shell, exactly the shape
the constant's comment says hits it unconditionally. The reason it reads as zero
is `keep_stronger` — `xss.script_tag` (90) is also on that field and outranks
`xss.base_href` (80), so the DOM walk never names the weaker construct. Taking
the masking rule away settles it:

```toml
[content_security]
rules_enabled  = ["xss.base_href", "xss.object_embed", "xss.dangling_open_tag"]
rules_disabled = ["xss.script_tag"]
```

`content-010` comes back as an `fp-log` at score 40 under `xss.base_href`, and
`content-009` is an `fp-log` at 40 under `xss.object_embed`. So the honest
statement is not "`xss.base_href` is free"; it is **"`xss.base_href` would flag
the one row in this corpus that carries its shape, and that row is already a
false positive for another reason, so switching it on adds nothing *to a posture
that still runs `xss.script_tag`*"**. An operator who silences `xss.script_tag`
to clear `content-010` and enables `xss.base_href` in the same change has not
cleared it.

**`xss.dangling_open_tag` is the one with genuine latent contact.** At
confidence 50 in a 0.5-weight family it scores 25, well under
`log_threshold = 40`, and it fires on `content-012` — a tenant theme settings
row storing a base64 `data:image/svg+xml` favicon. One benign row under the
line, no detection, no cost today. It is also masked on `xss-012` the same way
`xss.base_href` is masked on `content-010`: with `xss.script_tag` off it names
that attack row too, alongside `xss.event_handler`. Its `+0` detection is
therefore "adds nothing the stronger constructs are not already saying", not
"sees nothing".

## What the eighteen change about the two earlier documents

`docs/lane2-latent-pressure.md` said three of the ten false positives came from
keys "no amount of sweeping the switchable inventory will ever show". They are
switchable now and the sweep has shown them: `content-005` and `content-010`
belong to `xss.script_tag`, `content-011` to `xss.event_handler`, and each has a
named price for removing it. The `touched`/`over` classification that document
applies to the sixty-six extends to these fifteen unchanged: **none of them has
latent pressure.** Every benign row any of them fires on — four rows across two
rules — is already over a threshold and already counted. The classification of
the running set is now **70 clean, 0 latent, 11 already in the FP count**, across
81 rules rather than 66.

---

# What the seven flips did to the other thirty-one prices

`v0.2.188` turned seven default-off rules on. Every price in the batches above
was taken against a baseline that did not have them, and this document's own
evidence — `sql.stacked` reaching a block only by corroborating, and
`rce.backtick_cmd` turning four sub-threshold rows into false positives — is the
reason a price cannot be assumed to survive a baseline change. So the other
thirty-one carry a stale premise until something says otherwise.

Re-running all thirty-one would answer it and would mostly be thirty-one replays
producing the numbers already written down. What follows is the argument for
which of them *can* have moved, and the measurement that checks the argument
rather than trusting it.

## What actually changed between the two baselines

Two things, and only two.

**One: the seven rules' own signals.** Read straight out of the shipped baseline
report — every signal's `rule_key` is in `semantic_observations`, including
signals on rows that scored below every threshold — the seven fire on **twelve
attack rows and zero benign rows**:

| rule | rows |
|---|---|
| `nosql.comparison_operator` | `nosql-001` `nosql-004` `nosql-006` |
| `nosql.regex_operator` | `nosql-003` `nosql-011` |
| `nosql.logical_operator` | `nosql-005` `nosql-006` |
| `nosql.expr_operator` | `nosql-007` |
| `deser.php_object_injection` | `deser-006` `deser-015` |
| `traversal.sensitive_abs_ops` | `trav-005` `trav-020` |
| `xxe.entity_expansion` | `xxe-005` |

Eleven are the rows the flip recovered; `trav-020` is the twelfth, already
detected at 75 and unchanged by the extra signal.

**Two: the widened synthetic-view gate.** Flipping `traversal.sensitive_abs_ops`
also widened `NORMALISED_STRONG_STRUCTURE`, and unlike the seven signals that
widening is not confined to rows the seven fire on: a view that did not exist
before can hand *any* rule new text. Its reach is still bounded, and tightly.
The gate admits a synthetic view only when a default-on RCE or traversal pattern
matches it, so the only views the flip added are the ones matching the one
pattern the flip added —
`/etc/hosts\b|/proc/self\b|/proc/version\b|/proc/[0-9]+/`. A row that gains a
view therefore necessarily gains a `traversal.sensitive_abs_ops` signal, and
that signal is in the table above: `trav-005` and `trav-020`, both already in
the twelve.

Checked independently against the corpus text rather than inferred from the
gate: across all 390 rows, in raw, percent-decoded, base64-decoded and
hex-decoded form, exactly **two** carry a string matching that pattern, and they
are `trav-005` and `trav-020`.

**So the two baselines are identical on 378 of the 390 rows.**

## Why nothing on those twelve rows can corroborate either

A price could still move on the twelve — but only in one direction, and the
scoring model says which. `canonical(scope, field, attack, detector)` is an
**arg-max** over views, the per-family sum runs over *detectors*, and the
request roll-up across families is **max, not sum**. Two rules can therefore
only add up when they are in the same family and different detectors.

Every one of the thirty-one is either in a family none of the seven belongs to —
in which case the roll-up takes a max and no sum is possible — or in
`traversal`, `xxe`, `deserialization` or `nosql_injection`, which are
**single-detector families** (`traversal = 1.0`, `xxe_struct = 1.0`,
`deser_struct = 1.0`, `nosql_struct = 1.0`), which puts it in the same detector
as the newly-on rule and back under the arg-max.

There is no pair anywhere that can sum. The consequence is that no benign
column, no enforce column and no `touched` count can move at all, and the only
column that can is shadow `det` — downward, on a row a rule used to recover from
`blind` and that the baseline now recovers by itself.

## The measurement that checks it

Seven runs, not thirty-one. Each enables a group of default-off rules chosen so
that **no two members share a detector**, which is the condition under which
`best_match` cannot mask one member with another, so the per-row set difference
of `rule_keys_fired` against the baseline names exactly the group members that
fired. Nine detectors carry the thirty-one; the largest holds seven rules
(`ssti_struct`); seven groups cover all of them.

Two things fall out:

**Every one of the thirty-one reproduces its recorded benign contact, exactly.**
All thirty-one counts — from `xpath.bare_double_slash`'s 94 rows down to the
eleven rules at zero — match the numbers taken at `v0.2.181` on the nose, 31 of
31. That is the empirical form of the argument above, and it is the strongest
check available on the widened gate: had the widening handed any of them a new
view on any benign row, a count would have moved.

**Only four of the thirty-one touch any of the twelve rows at all:**

| rule | conf | rows in the twelve it fires on | the family already scoring those rows |
|---|--:|---|---|
| `xpath.bare_predicate` | 15 | `nosql-005` `nosql-006` `nosql-007` `xxe-005` | 45 / 55 / 75 / 65 |
| `xpath.bare_logical` | 20 | `nosql-005` `nosql-006` | 45 / 55 |
| `ldap.bare_wildcard` | 20 | `nosql-003` | 60 |
| `ldap.bare_logical` | 20 | `xxe-005` | 65 |

All four are cross-family — an XPath predicate rule firing on a Mongo operator,
an LDAP wildcard rule firing on a regex operator — at confidences of 15 to 20
against rows the expected family already scores at 45 to 75. The roll-up takes
the max, so none of them named the winning family before the flip and none of
them does now. None of the four recovered any of the twelve in the original
sweep (their recorded detection deltas are `+1` on `xpath-007` and `+0`, `+0`,
`+0`), so there is no detection for the new baseline to take away.

The group runs also reproduce every recorded bucket delta with no residue.
`combo-g1` recovers `sqli-019` `trav-016` `xxe-004` and flags `content-003`
`content-043` `content-047` `content-064` `content-109` and blocks `sqli-003` —
the exact union of `sql.stacked`, `traversal.plain_dotdot` and
`xxe.doctype_external` as recorded, minus `trav-005`. `combo-g2` recovers
`ssti-006` and `xpath-007` and flags `content-025` `content-046` `content-048`;
`combo-g3` recovers `rce-005` and `ssti-001` and flags `content-026`
`content-030` `content-038` `content-040`; `combo-g4` through `combo-g7` move
nothing, as their members' recorded prices say they should not.

## The one price that moved

**`traversal.plain_dotdot`, re-measured on its own against the shipped
baseline:**

| | det | FP | blocked | FPblk | touched | attacks recovered | benign flagged |
|---|--:|--:|--:|--:|--:|---|---|
| at `v0.2.181` | +2 | +2 | 0 | 0 | 2 | `trav-005` `trav-016` | `content-064` `content-109` |
| at `v0.2.192` | **+1** | +2 | 0 | 0 | 2 | `trav-016` | `content-064` `content-109` |

The batch-1 text already said its unique contribution was `trav-016` alone,
because `traversal.sensitive_abs_ops` recovers `trav-005` for free. That is now
the arithmetic as well as the prose: `traversal.sensitive_abs_ops` ships on, so
`trav-005` is in the baseline, and the rule buys **one attack for two false
positives**. `traversal.plain_dotdot` no longer even appears on `trav-005` —
both rules are in the single `traversal` detector, the canonical is an arg-max,
and 55 outranks 50, so it is masked there the same way `xss.base_href` is masked
on `content-010`. It was the worst bargain of the four costly batch-1 rules when it
read `+2/+2`; at `+1/+2` it is the only rule in the whole default-off set whose
detections are outnumbered by its false positives.

Nothing else moved. Thirty of the thirty-one prices above stand as recorded.

---

# Which zeros are masking

`xss.base_href` reads `touched = 0` on a corpus that contains its exact shape.
`traversal.plain_dotdot` stopped appearing on `trav-005` when a stronger
traversal rule went default-on. Both are the same effect — a rule that matched
and was never named — and until now the only answer to "how many more are there"
was a caveat saying nobody had looked. This section is the look.

It is not a rule-by-rule retry. The pipeline decides where masking can happen,
and the shipped baseline report decides which rows can be hiding what, so the
candidate set falls out of the two rather than out of a hunch.

## Masking happens in exactly one place

`SemanticDetector::detect` returns `Option<DetectionFinding>`
(`crates/waf-engine/src/checks/content_security/preprocess.rs:656`). **One rule
key per detector per view, and that is the whole of it.** Everything downstream
keeps every signal it is handed:

* `mod.rs:424` runs every detector on every view and pushes every finding —
  no dedup, no cap, no `break`;
* `scoring.rs:655` copies the signal slice into the verdict verbatim, and
  `engine.rs:817` serialises that slice into the `semantic_observations` row the
  corpus harness reads as `rule_keys_fired`;
* the `canonical` arg-max at `scoring.rs:470` collapses `(scope, field, attack,
  detector)` for the **score**, and `Group::best` / `best_specific` / the
  request roll-up / `reattribute_shared_construct` pick the single `rule_id` an
  operator sees on the event — none of them removes a signal from the list.

So a rule is invisible on a row if and only if one of its **own detector's**
rules took the slot it wanted, on the same view. Cross-detector cannot mask
(`xss.script_tag` and `xss.js_sink` are different detectors and both appear on
`xss-016`), and cross-view cannot mask (`rule_keys_fired` is a set over every
view, so a rule beaten on the raw view still shows if it wins on the
base64-decoded one).

## Where inside a detector the choice is made

Twelve sites, and they are all the same shape — propose every candidate, keep
one:

| site | file:line | what competes | winner |
|---|---|---|---|
| `best_match` | `detectors.rs:499` | every compiled row of one regex table | highest confidence, incumbent on a tie |
| `keep_stronger` | `xss_dom.rs:530` | the nine XSS DOM constructs | highest confidence, incumbent on a tie |
| dangling-tag fallback | `xss_dom.rs:846` | `xss.dangling_open_tag` vs any parsed construct | anything else at all — a hard `best.is_none()` gate, not a comparison |
| `classify_context` | `xss_js.rs:111` | `xss.js_exfil` vs `xss.js_sink` | exfil, falling back to sink when exfil is off |
| cross-context arg-max | `xss_js.rs:167` | the winners of every JS context on the view | highest confidence |
| `max_by_key` | `detectors.rs:3835` | every key the shell-AST walk fired | highest confidence, **last** on a tie |
| `walk.fire` | `detectors.rs:4288` | `rce_ast.cmd_subst` vs `rce_ast.cmd_subst_any` | whether the substitution's inner text is dangerous — mutually exclusive per substitution |
| `classify_statements` | `detectors.rs:2812` | `ast.stacked` vs everything else | stacked, and the other statements are never classified |
| `SetExpr::SetOperation` | `detectors.rs:2829` | `ast.union` vs the selects inside the union | union, and with union off the arm reports nothing |
| `classify_set_expr` | `detectors.rs:2836` | `ast.dangerous_fn` / `ast.tautology` / `ast.subquery` | an if/else-if chain in confidence order, over an `AstFlags` that holds all three |
| regex-vs-pickle | `detectors.rs:2403` | the deser regex table's winner vs the pickle walker's grade | highest confidence, regex on a tie |
| pickle grade | `detectors.rs:2440` | `deser.py_pickle_reduce_exec` vs `deser.py_pickle_dangerous_global` | reduce, falling back to the named grade when reduce is off |

`best_match` is called by all nine regex-table detectors
(`detectors.rs:663 897 1056 1206 1393 1658 1866 2067 2400`), which is why one
function covers seventy-nine of the hundred and fifteen keys.

Every one of these consults the operator's `RuleToggles` before it keeps a
candidate, which is the property that makes unmasking possible at all: take the
winner away in `rules_disabled` and the next-strongest enabled rule takes the
slot.

## What that makes provable, and where it stops

The winner outranks the loser on confidence at ten of the twelve sites, and at
the two `xss_*` fallbacks the loser is reported instead. So:

> A rule `B` can be missing from row `X` only if `X`'s `rule_keys_fired`
> contains a key of `B`'s own detector whose confidence is `>=` `B`'s.

That is a filter over the shipped baseline report, and it is what the candidate
set below is computed from. **Two sites break the confidence half of it, both
inside the SQL AST detector**, so `ast` is filtered on detector presence alone:

* `detectors.rs:2968` tries the numeric wrapper first and the single-quote
  breakout wrapper only `or_else` — so an `ast.subquery` (78) found under the
  numeric wrapper hides an `ast.dangerous_fn` (85) the quoted wrapper would have
  found;
* `detectors.rs:2982` **relabels**: on a view still carrying a comment marker the
  structural key is replaced by `ast.comment_obfusc`, at the structure's own
  confidence. The structure's key does not appear alongside it — it does not
  appear at all. `ast.comment_obfusc` is also the one key that is deliberately
  not switchable (`NON_SWITCHABLE_KEYS`, `detectors.rs:234`), so no
  `rules_disabled` can take the relabel away.

## Masking that is not a rule at all

Four more places lose a rule's chance to fire, and none of them is reachable
from `rules_enabled` / `rules_disabled` — they run identically in every sweep in
these two documents, so they are a standing limit on every number here rather
than an error in any particular one:

* **one blind decode per text.** `best_base64_candidate`
  (`preprocess.rs:484`) and `best_hex_candidate` (`preprocess.rs:509`) return the
  **first** structural candidate. A field carrying two base64 tokens yields one
  `BlindDecoded` view, and whatever the second one decodes to is never inspected.
* **one body extractor per request.** `extract_body_fields`
  (`struct_extract.rs:138`) dispatches multipart → JSON → GraphQL → XML → sniff
  in an if/else-if chain. A body that is two of those at once yields one
  extractor's leaves.
* **field and view caps.** The JSON/XML/GraphQL/multipart walks `break` at
  `max_fields`, and the per-field view cap drops frontier texts past
  `max_views`. The view cap records a miss and marks the request `degraded`; the
  field caps do not.
* **the XSS token detector depends on the DOM detector having run.**
  `XssDomDetector::detect` clears the JS-context stash before every early return
  (`xss_dom.rs:782`), so when the HTML parse budget or the input-size backstop
  declines a view, `xss.js_exfil` and `xss.js_sink` cannot fire on it — masked by
  a *different* detector, with no key of their own detector on the row to show
  for it.

## Where the candidates are, and why the sweep did not need them

The rule above cuts the problem down to almost nothing. **Thirteen of the 220
benign rows carry any Lane 2 signal at all in the shipped baseline** —
`content-005 -010 -011 -029 -030 -031 -033 -038 -040 -044 -059 -099 -100`, and
the other 207 name no rule of any detector. A benign `touched = 0` can only be
masking on one of those thirteen, and only for a rule of the detector that won
there: `ldap_struct` on `content-099`, `xpath_struct` on `content-100`,
`struct_rule` on `-044` and `-059`, `traversal` on `-031` and `-059`, `rce` on
`-029 -031 -033`, `rce_ast` on `-029 -030 -031 -038 -040`, and `xss_dom` on
`-005 -010 -011 -059`. **Six detectors — `ast`, `deser_struct`, `nosql_struct`,
`ssti_struct`, `xxe_struct`, `xss_js` — fire on no benign row anywhere**, so
every one of their rules is unmaskable on the benign half by construction, and
that is forty-eight of the hundred and fifteen keys before a single run.

That argument is worth having and it is not what the numbers below rest on. One
corpus replay in shadow mode takes twenty seconds, the whole inventory is a
hundred and fifteen rules, and a filter that has to be right is worse than a
sweep that does not have to be. **Every rule was run, not just the candidates.**

## The sweep

`tests/lane2/unmask.sh`, one run per rule: the rule enabled, **every other rule
of its own detector disabled**, every other detector left exactly as it ships.
Nothing of that detector is left to outrank it, so every row it matches names
it. 115 solo runs, 34 more for the default-off rules — a default-on rule is
named in the baseline already, a default-off one needs the run its price was
taken in — and the baseline, all shadow-only, because `rule_keys_fired` comes
from the `semantic_observations` rows and only shadow mode writes them.

```bash
tests/lane2/unmask.sh                          # every rule
tests/lane2/unmask.sh xss.base_href            # or just some
python3 tests/lane2/unmask.py --dir "$WORK/runs"
```

Isolating one rule rather than peeling the strongest away and re-running is
deliberate. A peel has to argue about tie-breaks — `best_match` keeps the
incumbent, the shell-AST walker's `max_by_key` keeps the *last* — and about how
deep is deep enough. Isolation leaves nothing to argue about.

**Recorded from `4fcb6d0b` (`v0.2.198`)**, release build, ports `185xx`,
Postgres on `15809`. The baseline run reproduces `tests/lane2/baseline.json`
exactly — shadow **139 / 10 / 2**, enforce **75 / 2 / 2** — and the shipped
posture's benign contact reproduces both documents' `touched` columns on the
nose: `rce_ast.cmd_subst` 5, `xss.script_tag` 3, `traversal.sensitive_abs` 2,
and one row each for `xss.event_handler`, `rce.piped_shell`, `rce.cmd_subst`,
`rce.shell_exec_flag`, `sql.union_select`, `sql.union_null`,
`ldap.filter_break_known_attr` and `xpath.func_axis`. `configs/default.toml`,
the corpus, `baseline.json` and every rule's `default_on` are untouched: the
sweep points `SRC` at a symlink mirror whose only real directory is `configs/`.
`NORMALISED_STRONG_STRUCTURE` reads the compiled-in `default_on` and not these
toggles (`detectors.rs:4314`), so **every run in this sweep sees the same views**
and the only thing that varies is which rule gets to name one.

## The answer: ten of the hundred and fifteen, and all ten are already priced

**105 of the 115 rules fire on exactly the benign rows they are recorded as
firing on.** Not one rule lost contact when it was isolated. The ten that gained
any gained **one row each**:

| rule | conf | recorded | true | the row | the rule that was covering it |
|---|--:|--:|--:|---|---|
| `xss.base_href` | 80 | 0 | **1** | `content-010` | `xss.script_tag` (90) |
| `ldap.filter_break_any_attr` | 60 | 0 | **1** | `content-099` | `ldap.filter_break_known_attr` (88) |
| `ldap.filter_group` | 35 | 0 | **1** | `content-099` | `ldap.filter_break_known_attr` (88) |
| `ldap.paren_adjacency` | 25 | 1 | **2** | `content-099` | `ldap.filter_break_known_attr` (88) |
| `ldap.bare_logical` | 20 | 71 | **72** | `content-099` | `ldap.filter_break_known_attr` (88) |
| `rce.backtick_cmd` | 78 | 5 | **6** | `content-031` | `rce.cmd_subst` (80) |
| `rce_ast.cmd_subst_any` | 50 | 14 | **15** | `content-031` | `rce_ast.cmd_subst` (78) |
| `sql.union_select` | 72 | 1 | **2** | `content-059` | `sql.union_null` (78) |
| `traversal.plain_dotdot` | 50 | 2 | **3** | `content-059` | `traversal.sensitive_abs` (68) |
| `xpath.bare_func` | 20 | 3 | **4** | `content-100` | `xpath.func_axis` (88) |

**Every one of the ten lands on a row that is already a false positive.**
`content-010` (45), `content-031` (79), `content-059` (68), `content-099` (88)
and `content-100` (88) are five of the ten false positives the baseline already
counts. **No masked rule touches a clean benign row, and none touches one of the
three `sub-threshold` rows.** So:

* the false-positive count of 10 cannot move, in either direction, from any of
  this;
* no rule's **clean** verdict changes — a rule recorded as touching nothing is
  touching nothing, in all 105 cases;
* `lane2-latent-pressure.md`'s classification — 70 clean, **0 latent**, 11
  already in the false-positive count — survives unchanged. The one default-on
  rule in the table, `sql.union_select`, was already in the bottom row for
  `content-044`; `content-059` puts it there twice.

The masking is real and it is uninteresting, which is the useful result. A
rule hidden under a stronger one is hidden on a row the stronger one has already
made expensive, so it adds no cost that is not already being paid — and it
starts costing the instant the rule covering it is switched off. The
`xss.base_href` warning in the section on the three default-off XSS constructs
is the general case: **switching off `ldap.filter_break_known_attr` to clear
`content-099` does not clear it if `ldap.bare_logical` is on**, and the same
holds for the other four pairs.

## The eleventh, which is not a rule at all

One more zero is masked, and no rule is doing it. **`rce_ast.interp_exec_flag`
(conf 82, default on) is recorded as touching nothing, and it matches
`content-033`** — a CI pipeline definition whose job steps are literal shell
invocations. The solo sweep cannot see it, because what hides it is the Lane 2
work budget: `content-033` is one of the nine rows that exhaust it, and the
shell-AST detector never reaches the view.

Measured rather than argued. Disabling the five SQL AST structures — the other
consumer of the shared AST attempt budget (`detectors.rs:2639` and `3820` take
from the same counters) — takes the degraded observation rows from **9 to 6**,
and exactly two rows gain a key:

| row | | gains |
|---|---|---|
| `content-033` | benign, already an `fp-log` at 41 | `rce_ast.interp_exec_flag` |
| `rce-017` | attack, already `detected` at 41 | `rce_ast.interp_exec_flag` |

Freeing every other budget-consuming detector as well (the XSS DOM parse, the
pickle walker) adds nothing further on the benign half and leaves the degraded
count at 6, so **on this corpus the budget hides exactly one benign rule-row
pair**, and the row it hides on is — again — already a false positive.

## The attack half, where masking is pervasive and the prices still hold

**35 of the 115 rules match attack rows they are not named on: 125 rule-row
pairs across 63 distinct attack rows.** That is a much bigger number than the
benign half's ten, and it changes nothing about any price. `det` and `blocked`
are bucket deltas — a row moving into `detected` — and a bucket delta is
computed correctly whether or not the rule that moved it is the one the report
names. What the masking does change is the **"attack rows it fires on"** column,
which is contact and not value, and three claims made in prose:

* **`traversal.plain_dotdot` fires on 17 attack rows, not one.** Its recorded
  `+1` detection (`trav-016`) stands — everything else it matches is a row the
  traversal family already scores higher on, `traversal.sensitive_abs` (68) and
  `traversal.sensitive_abs_brace` (68) both outranking it. Its bill is unchanged
  and its footprint is fifteen times what the table shows.
* **`xpath.bare_double_slash` reaches 30 attack rows** (26 recorded) and
  `ldap.bare_logical` **44** (36 recorded), on top of 94 and 72 benign rows. The
  verdict "pure noise with no upside whatsoever" is if anything understated.
* **Five of the eleven rules called "the eleven that do nothing whatsoever" do
  something.** `ldap.filter_break_any_attr` matches `content-099` and eight LDAP
  attacks; `ldap.filter_group` matches `content-099` and six; `ssti.py_class`
  matches `ssti-003`; `deser.java_pkg_generic` matches `deser-013`;
  `deser.php_array` matches `deser-015`. Every one is outranked by a default-on
  rule of its own detector on every row, which is why the enable sweep saw
  nothing. **Six of the eleven really do match nothing**, isolated or not:
  `deser.dotnet_formatter_name`, `deser.py_reduce`, `rce.mkfifo_revshell`,
  `sql.chr_freq`, `ssti.getclass`, `ssti.hash_delim`.

`deser.py_pickle_dangerous_global` gets its own correction. The section above
says it "has never been observed firing" and reads its zero as no information.
**It fires on `deser-007` and `deser-009`** the moment
`deser.py_pickle_reduce_exec` is off — which is the fallback
`pickle_finding` (`detectors.rs:2440`) documents, working exactly as its comment
says. The honest reading is not "the stack model never declines to model a
reduction"; it is that on this corpus it never declines *and is never asked to
report it*, because the stronger grade is always available. Its false-positive
surface is still unmeasured — the benign half contains no pickle — so the
"no information" verdict holds for the benign half and is now wrong for the
attack half.

`xss.data_html_url` goes the other way and is now settled rather than inferred.
With every other XSS DOM construct switched off it **still fires on nothing**,
including `xss-010`, which confirms the reading already given: the rule wants a
`data:text/html` URL in a real URL attribute of parsed HTML, and the corpus puts
it in a query parameter. That zero is absence, not masking, and it is the only
one of the eighteen code-decided rules for which that had been argued rather
than tested.

**Twenty of the 115 rules fire on nothing at all, isolated, on either half** —
`deser.dotnet_formatter_name`, `deser.php_object_gadget`, `deser.py_reduce`,
`ldap.null_byte_truncation`, `rce.mkfifo_revshell`, `rce.sensitive_read_brace`,
`rce_ast.heredoc_interp`, `rce_ast.proc_subst`, `rce_ast.cond_sensitive_path`,
`rce_ast.param_indirect`, `sql.chr_freq`, `sql.version_comment`,
`ssti.getclass`, `ssti.hash_delim`, `ssti.java_reflect_forname`,
`ssti.javax_script_engine`, `ssti.jinja_statement_sink`,
`traversal.sensitive_abs_brace`, `xpath.predicate_close_logic`,
`xss.data_html_url`. For those twenty the corpus says nothing, and now says so
with the masking excluded rather than confounded with it.
`rce_ast.interp_exec_flag` was the twenty-first until the budget run above took
it out.

---

# What this document does not establish

* **Three combinations were measured, out of every set anyone might ship.**
  Every other number is one rule against the baseline, and rows must not be
  added up: `sql.stacked` produced a block by corroborating with two rules
  already on, and `rce.backtick_cmd` produced three false positives by
  corroborating four rows from 39 to 78. Any set proposed for shipping needs its
  own run (`COMBO=` in `price-rules.sh`). The seven-rule free set, the two-rule
  XSS DOM set and the seven detector-disjoint groups have one; no other set does.
* **The prices in the first two batches were taken with no `default_on`
  changed**, through `rules_enabled` on an unmodified rule table at `v0.2.181`.
  `v0.2.187` changed seven of them and re-ran the corpus;
  [the section on the thirty-one](#what-the-seven-flips-did-to-the-other-thirty-one-prices)
  is the account of what that did to the rest, and it re-measured one rule and
  argued the other thirty from what the two baselines differ by. That argument
  rests on the scoring model — arg-max inside a detector, weighted sum across
  detectors of one family, max across families — and on `rules_enabled` being the
  only thing the group runs varied. A change to any of the three would invalidate
  it, and the seven group runs are what would have to be re-run.
* **220 benign rows are not a holdout.** They are a corpus of shapes this
  product has been burned by, which makes a false positive in it strong evidence
  and makes zero false positives in it weak evidence. `touched = 0` is the
  better reading of "found nothing to fire on" and it is still 220 requests, not
  a traffic sample. For the eleven default-off rules and the two code-decided
  rules that moved no column at all it is the whole of what is known about them.
* **A `touched = 0` can be a masked rule, and eleven of them are — all of them
  named.** Every detector reports one construct per view, so a weaker rule
  matching the same view as a stronger one is invisible in the shipped posture.
  [Every rule in the inventory has now been run in isolation](#which-zeros-are-masking):
  105 of 115 reproduce their recorded benign contact exactly, ten gain one
  already-false-positive row each, and one more (`rce_ast.interp_exec_flag`) is
  hidden by the work budget rather than by a rule. **Every benign `touched`
  number in this document and in `lane2-latent-pressure.md` is therefore either
  confirmed or corrected above**, and no rule recorded as touching nothing turned
  out to be touching a clean row. What is *not* settled by that sweep is
  everything a rule switch cannot reach: the `ast.comment_obfusc` relabel, the
  `SetOperation` arm, the shell walk's `cmd_subst`/`cmd_subst_any` choice, and
  the four view-and-field construction limits — one blind decode per text, one
  body extractor per request, the field caps, and the XSS token detector's
  dependence on the DOM detector. Those apply identically to every number here
  and are unmeasured by anything in either document.
* **No threshold, weight or scope change was measured.** Several verdicts above
  say a rule would be worth having under a different threshold or on a narrower
  route. None of those alternatives was run; each carries its own cost to the
  detections the current setting is buying.
* **The corpus carries no binary bodies** (`tests/lane2/README.md`), so any rule
  whose shape lives in non-UTF-8 bytes is under-measured here by construction.
  The pickle rules are the clearest case: the benign half contains no pickle at
  all, so `deser.py_pickle_dangerous_global`'s zero says nothing about its
  false-positive surface.
* **Nine corpus rows exhaust the Lane 2 work budget** and are marked `degraded`
  — `content-031` `content-033` `content-059` `rce-017` `rce-020` `xpath-002`
  `xpath-015` `xxe-009` `xxe-013` — so on those rows detection stops early and a
  rule that would have fired later in the budget is not counted. Some group runs
  add up to three more (`app-021` `app-024` `content-012` `content-025`
  `content-076` `sqli-019`). None of the twelve rows the seven flips reach is
  degraded in any run, which is why the thirty-one argument does not depend on
  this; nothing else is protected from it.
* **Detector weights were not varied.** Every number is at the shipped weights,
  so a rule in a 0.5-weight family is priced at half its confidence and would
  read differently in a family scored at 1.0.
* **`ast.comment_obfusc` is still outside every sweep.** It is a label rather
  than a rule and has no key, so the five AST prices above are prices for the
  structure *and* its relabelling together — `sqli-004` reports
  `ast.comment_obfusc`, and it is `ast.dangerous_fn` being taken away that makes
  the row stop blocking.
