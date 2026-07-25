# Fuzzing prx-waf

A WAF's entire job is to parse input an attacker chose. Every parser reached
from a request is therefore a remote-DoS surface, and hand-written unit tests
only cover the payloads someone thought of. This directory holds the
[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) harnesses that search for
the ones nobody thought of.

## Quick start

```bash
cargo install cargo-fuzz --locked          # needs a nightly toolchain
cd fuzz

cargo +nightly fuzz list                   # the seven targets

# Recommended invocation: throwaway corpus first, curated seeds second,
# dictionary on, length ramp off (see "Seeds, corpus, dictionaries" below).
cargo +nightly fuzz run struct_extract corpus/struct_extract seeds/struct_extract -- \
    -dict=dictionaries/struct_extract.dict -max_len=8192 -len_control=0 \
    -max_total_time=60
```

`fuzz/` is **its own cargo workspace** (the empty `[workspace]` table in
`fuzz/Cargo.toml`). The root workspace does not list it as a member, so
`cargo fmt --all`, `cargo clippy --workspace` and `cargo test --workspace` at
the repository root never see it. That isolation is deliberate: the fuzz crate
needs nightly and `libfuzzer-sys`, neither of which belongs in the stable
self-check gate. Run `cargo fmt`/`cargo clippy` from inside `fuzz/` to lint it.

## Targets

| Target | Surface | Why it matters |
| --- | --- | --- |
| `struct_extract` | JSON / XML / GraphQL / multipart body extraction (`serde_json`, `quick-xml`, `async-graphql-parser`, `multer`) | Recursive-descent parsers on a POST body. The GraphQL depth guards (`graphql_max_depth`, `MAX_GRAPHQL_RAW_OPENS`) are the code under test. |
| `preprocess_header` | Lane 2 decode chain on path / query / cookie / forwarding headers | Recursive URL decode, entity decode, comment strip, blind base64/hex, UTF-16 BOM transcode, shell de-obfuscation, plus the work budget bounding them. |
| `content_security` | `ContentSecuritySubsystem::evaluate_scoped`, both scopes, lane 2 on | The whole production request path: Lane 1 regex detectors plus the shell AST (`brush-parser`), SQL AST (`sqlparser`) and HTML DOM (`html5ever`) detectors. |
| `owasp_crs` | `OWASPCheck::check` against the real CRS rule set | The largest regex surface in the product. The finding to expect is a **hang** (catastrophic backtracking), not a panic. |
| `modsec_parse` | `SecRule` parser | Operator-supplied rule text; a panic here is an outage at reload time. |
| `smuggling_headers` | `gateway::smuggling::detect` | CL/TE desync header parsing. |
| `url_validator` | `validate_scheme_only` | SSRF validator's parse + scheme allowlist. |

### Input framing

Targets that need more than one input field use `[selector byte…][payload…]`
rather than a derived `Arbitrary` struct, so that **corpus files and crash
artifacts are readable**. You can `cat` a reproducer and see the attack payload;
you can add a seed with `printf`. The exact framing is documented at the top of
each target file, and the selector tables live in `fuzz/src/lib.rs`.

### Seeds, corpus, dictionaries

Three directories, deliberately separate:

* **`seeds/<target>/` — tracked, curated, read-only.** 165 files, ~12 KB total,
  largest 734 bytes. Real attack payloads lifted from the existing unit tests,
  benign counterparts (so the fuzzer also learns what *doesn't* trip a
  detector), and inputs sitting exactly on a parser guard — GraphQL/JSON/XML at
  nesting depth 63/64/65 (`MAX_PARSE_INPUT_DEPTH`), GraphQL at 255/256/257 raw
  brackets (`MAX_GRAPHQL_RAW_OPENS`), SQL and shell at 11/12/13 (`MAX_AST_NESTING`).
* **`corpus/<target>/` — gitignored, throwaway.** libFuzzer writes new units
  into the *first* corpus directory on the command line, so passing
  `corpus/<t> seeds/<t>` keeps the curated set clean while the working set grows
  freely. A ten-minute run adds several thousand files; none of that belongs in
  git.
* **`dictionaries/<target>.dict` — tracked.** Structural tokens (`$((`, `[[[[[[[[`,
  `<!DOCTYPE r [`, `--fuzzbound`, …). These matter more than run length: the
  parsers are protected by depth caps that random byte mutation essentially
  never reaches, and the dictionary is what lets the mutator assemble a document
  deep enough to test the cap.

Also pass **`-max_len=8192 -len_control=0`**. libFuzzer's default length ramp
starts near the average seed size and grows slowly; in a 5-minute run it never
got past ~160 bytes locally, which is far too short to nest 256 brackets. With
the ramp disabled the guards are actually exercised.

Keep new seeds small. A large seed slows every future run for the whole project;
if one has to be big to be interesting, say why in this file.

## Reproducing a crash

```bash
cargo +nightly fuzz run struct_extract fuzz/artifacts/struct_extract/crash-<hash>
cargo +nightly fuzz tmin struct_extract fuzz/artifacts/struct_extract/crash-<hash>
```

`tmin` shrinks the reproducer to the minimal input that still crashes — do this
before filing anything.

Two target-specific caveats:

* `owasp_crs` loads `rules/owasp-crs/` at startup (override with
  `PRX_WAF_FUZZ_RULES_DIR`). The rule set is part of the target's behaviour, so
  a reproducer is only valid against the rules snapshot that produced it —
  record the commit when filing.
* Stack overflows are reported by the sanitizer with a truncated stack. Rebuild
  with `--dev` and run under `rust-lldb` if you need the recursion cycle.
* **Stack size fidelity.** libFuzzer runs the target on the main thread (8 MiB
  by default), but production parses on a tokio worker with a 2 MiB stack —
  which is the stack size the depth guards in `detectors.rs` are written
  against. A recursion bug can therefore be reachable in production and *not*
  reproduce under the fuzzer. Run `ulimit -s 2048` in the shell before
  `cargo fuzz run` to match production; do it for any recursion-related
  investigation.

## Not currently fuzzable

These surfaces were considered and left out, with what each would need:

* **`validate_public_url_with_ips`** (and the deprecated `validate_public_url`
  that delegates to it) — calls `to_socket_addrs`, i.e. real DNS. Fuzzing it
  would be network-bound, non-deterministic and non-reproducible, and would
  point a resolver flood at the runner's nameserver. *Prerequisite:* make the
  resolver injectable (a trait parameter, or a `#[cfg(fuzzing)]` hook) so the
  private-range and blocked-hostname logic can be reached with a stub.
* **`struct_extract`'s individual extractors** (`extract_json`, `extract_xml`,
  `extract_graphql`, `extract_multipart`) — the module is private and the
  functions are `pub(super)` at best. They are reached indirectly through
  `semantic_preprocessor`, which is enough for crash-finding but costs coverage:
  the body must first survive media-type dispatch and the per-field budget.
  *Prerequisite:* `#[cfg(fuzzing)] pub use` of the extractors, or promoting
  `extract_body_fields` to `pub`.
* **Individual `SemanticDetector` implementations** — public types, but they
  take a `View<'_>` that only the preprocessor constructs, so a direct target
  would have to synthesise views and would fuzz a shape the pipeline cannot
  produce. Reached through `content_security` instead.
* **HTTP/1.1 and HTTP/2 wire parsing** — owned by pingora, upstream of the WAF.
  Bare CR/LF and pre-colon whitespace are rejected there and never reach
  `smuggling::detect`, so a target for them would be testing code this project
  does not own. Belongs in pingora's own fuzzing.
* **Rhai custom-rule scripts and WASM plugins** — operator-supplied code, not
  attacker input, and both run in engines with their own sandboxes and fuzzing.

## CI

`.github/workflows/fuzz.yml` runs each target for 60 s on every PR that touches
a fuzzed surface (regression only — it starts from the committed seeds and is
not expected to find anything new), and for 30 min per target on a weekly cron.
`workflow_dispatch` takes a `seconds` input for an ad-hoc soak.
Crash reproducers upload as build artifacts; they are deliberately **not**
committed, because a committed reproducer for an unfixed parser bug is a
published exploit.

## Results so far

First full run, 2026-07-25, on `main` at `30311ba` (16-core x86_64, ASan,
`-max_len=8192 -len_control=0`, dictionaries on):

| Target | Executions | Time | Edge coverage | Findings |
| --- | ---: | ---: | ---: | --- |
| `preprocess_header` | 1,221,273 | 15 min | 7,871 | none |
| `struct_extract` | 1,245,956 | 15 min | 13,260 | none |
| `content_security` | 103,208 | 15 min | 23,617 | none |
| `owasp_crs` | 287,324 | 15 min | 7,516 | none |
| `modsec_parse` | 580,303 | 90 s | — | none |
| `url_validator` | 548,831 | 90 s | — | none |
| `smuggling_headers` | 550,071 | 90 s | — | none |

No crash, hang or OOM. `slowest_unit_time_sec` was 0 for every target, i.e.
nothing took even one second — a meaningful negative result for the CRS
backtracking hypothesis.

Separately, 288 hand-built probes were run directly at the guard boundaries
(GraphQL / JSON / XML nesting from 60 to 5000; shell `$(`, `$((`, `` ` ``,
brace-group and brace-expansion nesting; SQL parenthesis, subquery and unary
chains; HTML tag nesting — each up to depth 4000), under both an 8 MiB and a
2 MiB stack. All were declined by the depth guards rather than parsed. The
guards in `struct_extract.rs` and `detectors.rs` hold.

The honest read: this is a *baseline*, not a clean bill of health. The
interesting depth-guard inputs came from hand-built probes and seeds, not from
the mutator, and `content_security` only manages ~100 exec/s. Real assurance
needs the weekly soak to accumulate.

## Is OSS-Fuzz worth applying for?

**Yes, but not yet — after the weekly soak has run clean for a few cycles.**

In favour: OSS-Fuzz supports Rust/`cargo-fuzz` natively, the targets here need
no network or database, and it would raise this repo's OpenSSF Scorecard
Fuzzing score from 0 to 10 — the metric on which Coraza already scores 10 while
ModSecurity and OWASP CRS score 0. It also brings CPU-months of fuzzing,
automatic bisection, and coordinated 90-day disclosure, which is the right
process for a remote-DoS bug in a WAF.

Prerequisites before applying:

1. **A public, reachable maintainer contact** for the security disclosures
   OSS-Fuzz will send. `SECURITY.md` covers this.
2. **A `Dockerfile` + `build.sh` under `projects/prx-waf/`** in the OSS-Fuzz
   repo. The only wrinkle is the `ip2region` git dependency — OSS-Fuzz builds
   offline-ish and prefers vendored or crates.io deps, so that dependency should
   be pinned or vendored first.
3. **`owasp_crs` needs its data files.** The target reads `rules/owasp-crs/` at
   startup; OSS-Fuzz runs targets from `$OUT`, so the rule set must be shipped
   as a target data dependency (or that one target excluded from the OSS-Fuzz
   set).
4. **Deflake first.** OSS-Fuzz files a bug per crash automatically. Landing a
   target that trips on its own rule-set drift generates noise that erodes
   trust in the whole integration.

Steps 2 and 3 are perhaps a day of work. Step 4 is the real gate, and it is the
argument for letting the weekly soak run first.
