# changelog.d

One file per change. These are assembled into a `CHANGELOG.md` version section
at release time and then deleted, so this directory is normally short and is
empty immediately after a release.

Name the file `<category>-<slug>.md`:

| Category     | Heading           |
| ------------ | ----------------- |
| `security`   | Security          |
| `added`      | Added             |
| `changed`    | Changed           |
| `deprecated` | Deprecated        |
| `removed`    | Removed           |
| `fixed`      | Fixed             |
| `breaking`   | Breaking Changes  |

The body is exactly one Markdown bullet. Continuation lines are indented by two
spaces; the text is copied into the changelog byte for byte, so wrap it the way
you want it read.

```markdown
- **A one-sentence lead in bold, stating what is now true.** Then the prose:
  what was wrong, why it was wrong, and what the fix costs. Line breaks are
  yours — nothing reflows this.
```

Validate before committing:

```bash
scripts/changelog.py check     # also runs as the first job in CI
scripts/changelog.py render    # see the section these will produce
```

Do not edit the `[Unreleased]` section of `CHANGELOG.md`. It exists as a
pointer to this directory precisely because it used to be the one file every
branch appended to. Full rationale in [CONTRIBUTING.md](../CONTRIBUTING.md).
