# Contributing to prx-waf

## Changelog entries go in `changelog.d/`, not in `CHANGELOG.md`

Add a file, do not edit the changelog.

```bash
$EDITOR changelog.d/fixed-header-decode-budget.md
scripts/changelog.py check
```

The name is `<category>-<slug>.md`. The category is one of `security`, `added`,
`changed`, `deprecated`, `removed`, `fixed`, `breaking`, and it decides which
`###` heading the entry lands under. The slug is lowercase words joined by
hyphens and is there so that `ls changelog.d/` reads as a list of changes; it
carries no other meaning, and in particular there is no issue number in it,
because this changelog has never cited one.

The body is one Markdown bullet, continuation lines indented by two spaces:

```markdown
- **A one-sentence lead in bold, stating what is now true.** Then the prose:
  what was wrong, why it was wrong, what the fix costs. Nothing reflows this
  text, so the line breaks you choose are the ones that ship.
```

### Why not just append to `[Unreleased]`

Because that section is a single file that every branch in flight writes to.
Two branches can touch no common source file, pass review independently, and
still conflict there — and one such conflict was merged and pushed to `main`
with eighty lines of markers still in it, because every gate in the pipeline
reads Rust source or Cargo metadata and none of them reads prose. Two branches
adding two files give git nothing to reconcile. The `[Unreleased]` heading
still exists in `CHANGELOG.md`, but its body is a static pointer to this
directory and nobody edits it.

Entries are grouped by category and, within a category, ordered by filename.
That ordering is arbitrary but deterministic, which is the property that
matters: it needs no counter, no timestamp and no coordination between
branches, so there is nothing to collide over.

Assembly happens at release time and is described in
[docs/RELEASING.md](docs/RELEASING.md). It is not part of
`.github/workflows/release.yml` — it runs on the operator's machine before the
tag is pushed, so a changelog that will not assemble fails on a terminal rather
than in the middle of a pipeline that has already started publishing.

---

## Before you commit

The one check that is cheap enough to run on every change:

```bash
scripts/check-conflict-markers.sh
```

It reads every tracked file for unresolved merge conflict markers and is the
first job in CI. Nothing else in the pipeline looks at non-Rust files.

The full gauntlet, which the release runbook also requires:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo check --all-features
cargo machete
cargo audit
cargo deny check
cargo test --workspace --all-features
```

Code standards — no `unwrap`/`expect` outside tests, no `std::sync::Mutex`, no
string-built SQL, a `// SAFETY:` comment on every `unsafe` block — are in
[CLAUDE.md](CLAUDE.md).

Commit subjects are imperative and describe the change, not the process.
Everything on GitHub is written in English.

## Reporting a vulnerability

Do not open an issue. [SECURITY.md](SECURITY.md) has the disclosure process.
