# What the Lane 2 rules that are already on are touching

[`docs/lane2-rule-pricing.md`](lane2-rule-pricing.md) priced the thirty-one Lane
2 rules that shipped off at the time, and its most useful column was the widest
one. `touched`
counts benign corpus rows a rule fires on **whatever bucket they end in**, and it
found something no other column could: eleven default-off rules that recover no
attack, produce no false positive, and fire on benign traffic anyway — the
largest of them, `xpath.bare_double_slash`, on 94 of the 220 benign rows. Those
rules read as free in every FP and fp-block column there is, and they are not
free — they are one weight change away from expensive.

That measurement was about rules nobody had ever run. This one asks the same
question about the sixty-six that have been running all along.

> **The inventory grew after this run and the answer did not change.**
> `v0.2.192` put the eighteen rules that decide in code on the switchable
> surface, so `rules semantic` lists **115 keys, 81 on and 34 off** rather than
> 97/66/31, and the fifteen of those eighteen that ship on now have prices of
> their own — including the two this document could name as false-positive
> sources and could not switch. Their `touched`/`over` classification is in
> [`lane2-rule-pricing.md`](lane2-rule-pricing.md#the-eighteen-rules-that-decide-in-code)
> and it lands where this one does: **none of the fifteen has latent pressure
> either.** Across all 81 running rules the split is 70 clean, 0 latent, 11
> already in the false-positive count. Every number in this document is a
> measurement of the sixty-six and is unchanged; the paragraphs the growth
> falsified are marked where they stand.

It cannot be asked in the shipped posture. A default-on rule is already firing,
so nothing moves when you look at it: no bucket delta, no FP count, no
fp-block count. A rule quietly in contact with a third of the benign corpus and
a rule that never fires produce byte-identical reports. The only way to tell
them apart is to take the rule away and see what stops.

## How to reproduce

```bash
DIRECTION=disable tests/lane2/price-rules.sh                  # all 66 then, all 81 now
DIRECTION=disable tests/lane2/price-rules.sh rce_ast.cmd_subst
python3 tests/lane2/price-rules.py --dir "$WORK/pricing" --direction disable
```

`DIRECTION=disable` reads the default-**on** inventory out of the binary and
substitutes `rules_disabled` where the enable sweep substitutes `rules_enabled`.
The baseline run is the same untouched tree in both directions; only the
subtraction reverses, so every column still reads as **what the rule does when it
is on** — `det` is detections it is responsible for, `FP` is false positives it
is responsible for, `touched` is the benign rows it fires on. A new column,
`over`, splits `touched` into the rows that are over a threshold today and the
rows that are not. The second number is the one that has never been measured.

**Recorded from `b1cc7f3c` (`v0.2.188`)**, release build, 2×67 corpus replays.
The baseline run reproduces `tests/lane2/baseline.json` exactly — shadow 139
detected / 10 false positives / 2 blocking, enforce 75 blocked / 2 / 2 — and
every number below is read against it. `configs/default.toml`, the corpus,
`baseline.json` and every rule's `default_on` are untouched by this work: the
sweep points `SRC` at a symlink mirror of the tree whose only real directory is
`configs/`.

One change to the harness was needed and is committed with this work. The
enforce-mode sanity gate used to assert that one hard-coded `UNION SELECT`
returns 403, which proves enforcement is in force by proving one particular rule
is loaded. Those are different claims, and the disable sweep separates them:
take `sql.union_null` away and the probe returns 200 while enforcement works
perfectly. The gate now sends three probes from three families and requires one
of the three to block.

## The answer, before the table

**There is no latent pressure in the default-on set.** Of the sixty-six rules,
fifty-seven touch none of the 220 benign rows. The nine that touch anything
touch fourteen rows between them, and eleven of those fourteen are already over
a threshold and already counted in the ten false positives. The entire hidden
population — benign contact that no existing number can see — is **three rows on
one rule**.

| classification | rules | + the fifteen code-decided (`v0.2.192`) |
|---|--:|--:|
| **clean** — fires on no benign row | 57 | 70 |
| **latent pressure** — fires on benign rows, crosses nothing | **0** | **0** |
| **already in the FP count** — at least one benign row over a threshold | 9 | 11 |

The third column is the same classification over the whole running set of 81
once the code-decided rules could be swept. The two rules it adds to the bottom
row are `xss.script_tag` (three benign rows, all over a threshold) and
`xss.event_handler` (one, over). The middle row stays empty.

Compare the same three buckets on the default-off set, where eleven rules land
in the middle row and one of them carries 94 rows. The default-on set does not
have that shape anywhere.

This is a statement about *contact*, not about value. Twenty-eight of the
sixty-six move nothing at all on this corpus — no benign row, no detection, no
block. That is no information rather than a clean bill, exactly as the eleven
inert default-off rules were.

## The sixty-six

Sorted by `touched`, then by family in the order `configs/default.toml` declares
them. `det` and `blocked` are what the tree loses when the rule is removed, i.e.
what the rule is carrying today.

| rule_key | family | conf | touched | of which over a threshold | det | blocked | class |
|---|---|--:|--:|--:|--:|--:|---|
| `rce_ast.cmd_subst` | `rce` | 78 | **5** | 2 | +0 | +0 | already in the FP count |
| `traversal.sensitive_abs` | `traversal` | 68 | **2** | 2 | +11 | +0 | already in the FP count |
| `sql.union_null` | `sql_injection` | 78 | **1** | 1 | +0 | +2 | already in the FP count |
| `sql.union_select` | `sql_injection` | 72 | **1** (→ 2, [below](#two-rules-the-table-understates-and-nothing-else)) | 1 (→ 2) | +1 | +0 | already in the FP count |
| `rce.shell_exec_flag` | `rce` | 82 | **1** | 1 | +1 | +0 | already in the FP count |
| `rce.cmd_subst` | `rce` | 80 | **1** | 1 | +1 | +0 | already in the FP count |
| `rce.piped_shell` | `rce` | 78 | **1** | 1 | +0 | +0 | already in the FP count |
| `ldap.filter_break_known_attr` | `ldap_injection` | 88 | **1** | 1 | +1 | +1 | already in the FP count |
| `xpath.func_axis` | `xpath_injection` | 88 | **1** | 1 | +2 | +2 | already in the FP count |
| `sql.into_outfile` | `sql_injection` | 95 | 0 | 0 | +0 | +0 | clean |
| `sql.dangerous_fn` | `sql_injection` | 85 | 0 | 0 | +1 | +3 | clean |
| `sql.version_comment` | `sql_injection` | 70 | 0 | 0 | +0 | +0 | clean |
| `rce.reverse_shell` | `rce` | 92 | 0 | 0 | +1 | +2 | clean |
| `rce_ast.reverse_shell` | `rce` | 90 | 0 | 0 | +0 | +1 | clean |
| `rce_ast.heredoc_interp` | `rce` | 82 | 0 | 0 | +0 | +0 | clean |
| `rce_ast.interp_exec_flag` | `rce` | 82 | 0 (→ 1, [below](#two-rules-the-table-understates-and-nothing-else)) | 0 (→ 1) | +0 | +0 | clean |
| `rce_ast.cmd_chain_injection` | `rce` | 80 | 0 | 0 | +2 | +0 | clean |
| `rce_ast.pipe_to_interp` | `rce` | 80 | 0 | 0 | +0 | +0 | clean |
| `rce.fetch_exec` | `rce` | 75 | 0 | 0 | +0 | +0 | clean |
| `rce_ast.proc_subst` | `rce` | 72 | 0 | 0 | +0 | +0 | clean |
| `rce.sensitive_read` | `rce` | 70 | 0 | 0 | +2 | +0 | clean |
| `rce.sensitive_read_brace` | `rce` | 70 | 0 | 0 | +0 | +0 | clean |
| `rce.sensitive_read_brace_cmd` | `rce` | 70 | 0 | 0 | +1 | +0 | clean |
| `rce_ast.cond_sensitive_path` | `rce` | 70 | 0 | 0 | +0 | +0 | clean |
| `rce_ast.sensitive_read` | `rce` | 70 | 0 | 0 | +0 | +0 | clean |
| `rce_ast.param_indirect` | `rce` | 60 | 0 | 0 | +0 | +0 | clean |
| `traversal.overlong` | `traversal` | 82 | 0 | 0 | +1 | +2 | clean |
| `traversal.encoded_dotdot` | `traversal` | 75 | 0 | 0 | +0 | +0 | clean |
| `traversal.sensitive_abs_brace` | `traversal` | 68 | 0 | 0 | +0 | +0 | clean |
| `traversal.sensitive_abs_ops` | `traversal` | 55 | 0 | 0 | +1 | +0 | clean |
| `xxe.entity_external` | `xxe` | 90 | 0 | 0 | +10 | +10 | clean |
| `xxe.param_entity_def` | `xxe` | 80 | 0 | 0 | +0 | +0 | clean |
| `xxe.entity_expansion` | `xxe` | 65 | 0 | 0 | +1 | +0 | clean |
| `nosql.query_operator` | `nosql_injection` | 90 | 0 | 0 | +6 | +5 | clean |
| `nosql.expr_operator` | `nosql_injection` | 75 | 0 | 0 | +1 | +0 | clean |
| `nosql.regex_operator` | `nosql_injection` | 60 | 0 | 0 | +2 | +0 | clean |
| `nosql.comparison_operator` | `nosql_injection` | 55 | 0 | 0 | +2 | +0 | clean |
| `nosql.logical_operator` | `nosql_injection` | 45 | 0 | 0 | +1 | +0 | clean |
| `ssti.freemarker_exec` | `ssti` | 95 | 0 | 0 | +1 | +1 | clean |
| `ssti.java_reflect_forname` | `ssti` | 90 | 0 | 0 | +0 | +0 | clean |
| `ssti.spel_type_java` | `ssti` | 90 | 0 | 0 | +1 | +1 | clean |
| `ssti.javax_script_engine` | `ssti` | 88 | 0 | 0 | +0 | +0 | clean |
| `ssti.jinja_sink` | `ssti` | 88 | 0 | 0 | +0 | +0 | clean |
| `ssti.jinja_statement_sink` | `ssti` | 85 | 0 | 0 | +0 | +0 | clean |
| `ssti.py_sandbox_dunder` | `ssti` | 85 | 0 | 0 | +0 | +0 | clean |
| `ssti.erb_scriptlet_exec` | `ssti` | 82 | 0 | 0 | +1 | +1 | clean |
| `ssti.py_import` | `ssti` | 82 | 0 | 0 | +0 | +0 | clean |
| `ldap.auth_bypass_wildcard` | `ldap_injection` | 90 | 0 | 0 | +0 | +0 | clean |
| `ldap.filter_break_logical` | `ldap_injection` | 90 | 0 | 0 | +3 | +3 | clean |
| `ldap.hex_escape_break` | `ldap_injection` | 85 | 0 | 0 | +0 | +0 | clean |
| `ldap.hex_escape_meta_pair` | `ldap_injection` | 82 | 0 | 0 | +0 | +0 | clean |
| `ldap.null_byte_truncation` | `ldap_injection` | 80 | 0 | 0 | +0 | +0 | clean |
| `xpath.auth_bypass_func` | `xpath_injection` | 90 | 0 | 0 | +1 | +1 | clean |
| `xpath.node_axis_union` | `xpath_injection` | 90 | 0 | 0 | +1 | +1 | clean |
| `xpath.quote_tautology` | `xpath_injection` | 88 | 0 | 0 | +5 | +7 | clean |
| `xpath.axis_predicate_func` | `xpath_injection` | 85 | 0 | 0 | +0 | +0 | clean |
| `xpath.predicate_close_logic` | `xpath_injection` | 85 | 0 | 0 | +0 | +0 | clean |
| `deser.dotnet_binaryformatter_b64` | `deserialization` | 90 | 0 | 0 | +1 | +1 | clean |
| `deser.java_gadget_class` | `deserialization` | 90 | 0 | 0 | +2 | +2 | clean |
| `deser.java_serial_b64` | `deserialization` | 90 | 0 | 0 | +5 | +5 | clean |
| `deser.py_pickle_global_exec` | `deserialization` | 90 | 0 | 0 | +0 | +0 | clean |
| `deser.dotnet_gadget` | `deserialization` | 88 | 0 | 0 | +1 | +1 | clean |
| `deser.java_hex_magic` | `deserialization` | 88 | 0 | 0 | +1 | +1 | clean |
| `deser.php_object_gadget` | `deserialization` | 88 | 0 | 0 | +0 | +0 | clean |
| `deser.php_phar` | `deserialization` | 85 | 0 | 0 | +1 | +1 | clean |
| `deser.php_object_injection` | `deserialization` | 60 | 0 | 0 | +2 | +0 | clean |

### Two rules the table understates, and nothing else

The isolation sweep in
[`lane2-rule-pricing.md`](lane2-rule-pricing.md#which-zeros-are-masking)
re-derived every `touched` count above with each rule's own detector cleared of
everything that could outrank it. **Sixty-four of the sixty-six are exact.** Two
are not, and neither moves a bucket:

* **`sql.union_select` touches 2 benign rows, not 1.** It also fires on
  `content-059`, where `sql.union_null` (78) outranks it (72) in the single
  `struct_rule` detector. `content-059` is already a false positive on
  `sql.union_null` and `traversal.sensitive_abs`, so the row was counted; the
  attribution was not.
* **`rce_ast.interp_exec_flag` touches 1 benign row, not 0** — `content-033`,
  and this one is not a rule outranking a rule. `content-033` exhausts the Lane 2
  work budget, exactly as the caveat at the end of this document warns, and the
  shell-AST detector never reaches the view. Taking the SQL AST layer away frees
  the shared attempt budget and the signal appears. `content-033` is already a
  false positive on `rce.shell_exec_flag`.

So the nine rules with benign contact become nine rules and **fifteen** rows
rather than fourteen, twelve of them already over a threshold rather than
eleven, and the hidden population is still **three rows on one rule**. The
`over` split, the false-positive attribution, and the **0 latent** row of the
classification are all unchanged: both corrections land on rows that are already
false positives.

### The table is confirmed twice

`touched` can also be read straight out of the baseline run: the observation
rows carry every signal's `rule_key`, including signals on requests that scored
below every threshold, so counting benign rows whose `rule_keys_fired` contains
a key gives the same number without disabling anything. The two derivations were
compared for all sixty-six keys and agree on every one, `touched` and `over`
alike. They are not the same measurement — the direct read cannot say what a row
would score *without* the rule, which is the whole of the false positive
attribution below — but agreeing means neither the sweep nor the report is
dropping signals.

## Where the ten false positives come from

The disable sweep answers this exactly, because for each false positive it can
say what the row scores when a rule is taken away. `still an FP` means the row
stays over `log_threshold` on its remaining signals, so that rule is a
contributor and not the cause.

| row | score | rules that fired | what removing each one does |
|---|--:|---|---|
| `content-099` | 88 | `ldap.filter_break_known_attr` | **clean** — sole cause, and this is one of the two blocking FPs |
| `content-100` | 88 | `xpath.func_axis` | **clean** — sole cause, and this is the other blocking FP |
| `content-031` | 79 | `rce.cmd_subst`, `rce_ast.cmd_subst`, `traversal.sensitive_abs` | 68 / 68 / 79 — **no single removal clears it** |
| `content-029` | 78 | `rce.piped_shell`, `rce_ast.cmd_subst` | 39 / 39 — **either removal clears it**, to sub-threshold |
| `content-059` | 68 | `sql.union_null`, `traversal.sensitive_abs`, `xss.script_tag` (+ `sql.union_select`, masked) | 68 / 45 / n-a — **no single removal clears it**, and taking `sql.union_null` away exposes `sql.union_select` on the same field |
| `content-005` | 45 | `xss.script_tag` | not switchable by this run's binary — **clean**, measured at `v0.2.192` |
| `content-010` | 45 | `xss.script_tag` | not switchable by this run's binary — **clean**, measured at `v0.2.192` |
| `content-011` | 43 | `xss.event_handler` | not switchable by this run's binary — **clean**, measured at `v0.2.192` |
| `content-033` | 41 | `rce.shell_exec_flag` (+ `rce_ast.interp_exec_flag`, budget-masked) | **clean** — sole cause at the shipped budget; the second rule is on a view the row never reaches |
| `content-044` | 36 | `sql.union_select` | **clean** — sole cause |

Five of the ten have a single named rule whose removal returns the row to
`clean`. One (`content-029`) has two rules either of which is sufficient to
clear it, because the RCE family needs both its detectors to reach 78 and
removing either leaves 39. Two (`content-031`, `content-059`) are carried by
more than one rule independently and no single switch fixes them. Three
(`content-005`, `-010`, `-011`) came from rules this config surface did not
reach.

> **The last three are answered now.** `v0.2.192` made both keys switchable and
> the sweep in
> [`lane2-rule-pricing.md`](lane2-rule-pricing.md#xssscript_tag-is-the-most-expensive-rule-in-lane-2-and-the-most-valuable)
> ran them: removing `xss.script_tag` returns `content-005` and `content-010` to
> `clean`, and removing `xss.event_handler` returns `content-011` to `clean`. So
> **eight of the ten false positives have a single switch that clears them**, not
> five. The price of using those two switches is eight and four detections
> respectively, which is the largest detection cost attached to any false
> positive in this table. `content-059` also loses its `xss.script_tag` signal
> and stays a false positive at 68 on the other two rules, exactly as the `n-a`
> in its row anticipated.

### The rules this table cannot include

At the time of this run `prx-waf rules semantic` listed 97 keys, 66 on and 31
off. The engine emits fourteen more on this corpus that were in no keyed table
and are therefore in neither sweep:

| keys | detector |
|---|---|
| `ast.tautology` `ast.union` `ast.comment_obfusc` `ast.dangerous_fn` `ast.stacked` `ast.subquery` | the `sqlparser-rs` AST SQLi detector |
| `xss.script_tag` `xss.event_handler` `xss.svg_onload` `xss.iframe_srcdoc` `xss.js_url` `xss.js_sink` `xss.js_exfil` | the two XSS detectors (`xss_dom`, `xss_js`) |
| `deser.py_pickle_reduce_exec` | the pickle opcode walker |

This was deliberate and the CLI said so — those detectors decide in code rather
than from a table, and naming one in `rules_enabled` or `rules_disabled` was
refused at startup like any other unknown key. It is worth stating here anyway,
because **three of the ten false positives and part of a fourth come from two of
those keys**, and no amount of sweeping the switchable inventory will ever show
that. `xss.script_tag` fires on three benign rows and eight attack rows,
`xss.event_handler` on one benign row and five attack rows. Turning either off
meant turning off the XSS family.

> **Superseded in `v0.2.192`, and priced since.** Thirteen of those fourteen keys
> are switchable now, along with five more the corpus never reached, so the
> inventory is 115 keys rather than 97 and every sweep in this document can be
> pointed at them. The measurements above are unchanged — the default posture is
> byte-identical, and this section describes what could be *reached*, not what
> fired.
>
> The sentence "no amount of sweeping the switchable inventory will ever show
> that" is the one this document got wrong, and it was wrong the moment the keys
> got a switch. The sweep exists:
> [`lane2-rule-pricing.md`](lane2-rule-pricing.md#the-eighteen-rules-that-decide-in-code)
> prices all eighteen. It confirms the two counts stated above — `xss.script_tag`
> on three benign and eight attack rows, `xss.event_handler` on one benign and
> five attack rows — and adds what "turning either off" now actually costs, which
> is twelve detections and one block for the two together and not the whole XSS
> family.
>
> The one key still outside the surface is `ast.comment_obfusc`, which is a label
> the AST detector puts on whichever structure it already matched rather than a
> rule with a confidence of its own; disabling the structure reaches it.

## The five rules with the most benign contact

Only nine rules have any, so this is very nearly the whole list.

1. **`rce_ast.cmd_subst`** (conf 78, `brush-parser` shell AST) — five rows, and
   the only rule in the set with contact that is not already counted. It fires
   on `content-029` (a README documenting `curl … | sh`), `content-031`
   (container docs showing `-v /etc/passwd:/etc/passwd:ro`), `content-030` (a
   TLS-rotation runbook), `content-038` (a bug report whose repro is `curl … |
   jq`) and `content-040` (a code-review comment about hoisting
   `$(git rev-parse HEAD)`). All five are the same shape: **a shell command
   inside a documentation field**, which parses into exactly the tree an attack
   parses into, because it is one.
2. **`traversal.sensitive_abs`** (conf 68) — two rows, both already false
   positives, and it carries eleven detections, more than any other rule in the
   set. It fires on `content-031` (the `/etc/passwd` bind mount again) and
   `content-059` (a log shipper forwarding nginx lines that record other
   people's probes).
3. **`ldap.filter_break_known_attr`** (conf 88) — one row, `content-099`, an
   LDAP admin page saving `(&(objectClass=person)(uid=jsmith))`. One of the two
   blocking false positives.
4. **`xpath.func_axis`** (conf 88) — one row, `content-100`, a document-transform
   tool saving XPath. The other blocking false positive.
5. **`rce.cmd_subst`**, **`rce.piped_shell`**, **`rce.shell_exec_flag`**,
   **`sql.union_null`**, **`sql.union_select`** — one row each, all already
   counted, all the same documentation-and-code-review shapes.

Nothing here is a case of "fires on a pile of benign traffic and gets away with
it". The largest pile is five rows out of 220.

### The one piece of latent contact there is

Three rows — `content-030`, `content-038`, `content-040` — sit at score **39**
against `rce.log_threshold = 40`. All three are `rce_ast.cmd_subst` alone:
confidence 78, RCE detector weight 0.5, so 39, and one point below the line.
They are the entire content of the `sub-threshold` benign bucket.

These are the same three rows the enable sweep reached from the other side:
`docs/lane2-rule-pricing.md` records that switching on `rce.backtick_cmd`
corroborates all three to 78 and turns them into false positives, for one
recovered attack. The disable sweep says the rule already sitting on them is
`rce_ast.cmd_subst`, and that it needs no help from a second rule — two points
of its own confidence would do it.

That is the sharpest edge in the default-on set, and it is worth naming
precisely rather than dramatising. **Raising `rce_ast.cmd_subst`'s confidence
from 78 to 80 — or lowering `rce.log_threshold` from 40 to 39 — turns three
clean-looking rows into three new logged false positives, taking the FP count
from 10 to 13.** No blocking changes: 39 is nowhere near `block_threshold = 80`.
It is a 30% swing in the number that everyone watches, available for one point
of confidence, and today nothing reports it.

## What blocks first when `rollout_bps` moves

`rollout_bps` does not change any score. It changes whether a `Block`
recommendation is acted on, so the first requests to be affected are exactly the
benign rows whose recommendation is already `Block` — which the enforce baseline
has been measuring all along:

| row | score | rule | what it is |
|---|--:|---|---|
| `content-099` | 88 | `ldap.filter_break_known_attr` | LDAP admin page saving a real search filter |
| `content-100` | 88 | `xpath.func_axis` | transform tool saving a real XPath expression |

Both are single-detector families running at weight 1.0, so a confidence of 88
*is* a request score of 88, over `block_threshold = 80` on one rule with nothing
corroborating. Both are tools whose declared input language is the attack
grammar. No detector improvement fixes that; it is a deployment-scope question
and `enforcement_overrides` is where the answer goes.

The interesting number is what is behind them. Sorting the benign half by score
against `block_threshold = 80`:

| row | score | distance to a block | rules |
|---|--:|--:|---|
| `content-031` | 79 | **1** | `rce.cmd_subst` (80) + `rce_ast.cmd_subst` (78) |
| `content-029` | 78 | **2** | `rce.piped_shell` (78) + `rce_ast.cmd_subst` (78) |
| `content-059` | 68 | 12 | `traversal.sensitive_abs` (68) |
| `content-005` / `-010` | 45 | 35 | `xss.script_tag` |
| `content-011` | 43 | 37 | `xss.event_handler` |
| `content-033` | 41 | 39 | `rce.shell_exec_flag` |
| `content-044` | 36 | 44 | `sql.union_select` |

`content-031` and `content-029` are one and two points from a 403, and both are
already at the *hard* part: the RCE family's block rule is
`0.5·c_rce + 0.5·c_rce_ast ≥ 80`, requiring both detectors to corroborate on the
same field, and on these two rows **both detectors already do**. The
two-detector requirement that keeps RCE's enforce rate at 10% is not what is
protecting these rows. Only the last point of arithmetic is:
`(80 + 78) / 2 = 79`.

So the honest answer to "which rules bite first" is: `ldap.filter_break_known_attr`
and `xpath.func_axis` bite immediately and are already counted, and the next two
in line are **`rce.cmd_subst` + `rce_ast.cmd_subst` on `content-031`** and
**`rce.piped_shell` + `rce_ast.cmd_subst` on `content-029`** — both of which turn
into blocking false positives on a two-point change to any RCE confidence, any
RCE weight, or `rce.block_threshold`. `rce_ast.cmd_subst` is in both pairs, and
in the three sub-threshold rows as well: it is the single rule most exposed to a
small change anywhere in the RCE family's scoring.

## What this does not say

**Nothing here is a recommendation to switch a rule off, and nothing was
switched.** The corpus is 220 benign rows and a deployment is not. A rule that
looks inert here may be the only thing standing between a route and the shape it
was written for — twenty-eight of the sixty-six moved nothing at all, and that
is a gap in the corpus at least as much as a fact about the rules.

Two limits on the `touched` numbers specifically:

* **Three benign rows are `degraded`** — `content-031`, `content-033` and
  `content-059` exhausted the Lane 2 work budget, so on those rows detection
  stopped early and other rules may have had contact that was never evaluated.
  All three are already false positives, so this cannot hide a clean row, but it
  can understate `touched` for rules that would have fired later in the budget.
* **The fourteen out-of-inventory keys are not in the table**, so the sixty-six
  rows are the switchable set and not the whole engine at the time of this run.
  On the benign half those keys contribute four rows of contact, three of which
  are false positives. Thirteen of the fourteen entered the inventory in
  `v0.2.192`; the later sweep exists and is
  [`lane2-rule-pricing.md`](lane2-rule-pricing.md#the-eighteen-rules-that-decide-in-code),
  which prices those thirteen and five more the corpus had never reached. It
  reports the same four rows of benign contact this run saw from outside, so the
  two agree, and it adds one classification this document could not: **a rule can
  read as zero because a stronger construct on the same field outranks it, not
  because it found nothing.** `xss.base_href` is the worked example.
  **Every row of the table above has since been checked for it.**
  [`lane2-rule-pricing.md`](lane2-rule-pricing.md#which-zeros-are-masking) ran
  all 115 rules in isolation — each with every other rule of its own detector
  switched off — and the sixty-six survive with one correction, immediately
  below. Two limits remain and neither is a rule outranking a rule: the Lane 2
  work budget (the bullet above, and it hides one more row — see below), and the
  four view-and-field construction paths no rule switch reaches.

`docs/lane2-blind-spots.md` remains the attack-side companion; this document
says nothing about what Lane 2 misses.
