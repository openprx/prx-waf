- **CI refuses a tree with unresolved merge conflict markers in it.** A
  `CHANGELOG.md` holding eighty lines of markers was pushed to `main` and every
  gate passed, because fmt, clippy, check, machete, test, audit and deny
  between them read Rust source and Cargo metadata and nothing reads prose.
  Prose is precisely where parallel branches collide, and the commit was caught
  days later by accident. `scripts/check-conflict-markers.sh` reads every
  tracked file; it is the first job in `ci.yml` and gates the rest, so a
  conflicted tree costs a runner-minute rather than a thirty-minute build, and
  it runs again in the release gate because `ci.yml` triggers on branches and a
  tag can point anywhere.

  The scan keys on the angle markers alone. Git emits all of them together for
  every conflict it leaves behind, so nothing is lost, whereas a bare
  seven-equals line is ordinary content — a setext underline, an ASCII rule in
  a docstring — and this repository has seven of those today. Requiring the
  angles is what keeps the check at zero false positives, and a check with
  false positives is a check people learn to scroll past.
