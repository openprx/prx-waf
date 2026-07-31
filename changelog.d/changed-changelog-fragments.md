- **Changelog entries are written as one file per change under `changelog.d/`,
  not appended to `[Unreleased]`.** That section was the single place every
  branch in flight wrote to, so two branches that touched no common source file
  still collided there, and one such collision was committed to `main` with its
  conflict markers intact. A fragment is a plain Markdown file named
  `<category>-<slug>.md` whose body is one bullet; two branches adding entries
  now add two files and git has nothing to reconcile.

  `scripts/changelog.py release <version>` groups the fragments by the category
  in their names, concatenates them verbatim under one `###` heading each, and
  splices the result into `CHANGELOG.md` as a new version section. It runs at
  step 3 of `docs/RELEASING.md`, on the operator's machine, before the tag
  exists — `release.yml` is a six-job pipeline and an assembly step inside it
  would be a seventh way for a release to fail after it had already started
  publishing. Nothing in the release workflow changed.

  towncrier and scriv were the serious alternatives and both would have worked;
  each needs a Python install in CI and a config file re-encoding the heading
  format that `release.yml` already pins, to do a job that is grouping files by
  a filename prefix. towncrier additionally keys fragments on an issue number
  that this changelog has never once cited. changesets wants to own version
  bumping and publishing, which `[workspace.package] version` and the tag-match
  gate already own, and wraps each fragment in YAML front matter; changie and
  reno put the prose inside a YAML scalar, where a forty-line entry stops being
  reviewable. git-cliff generates from commit messages rather than fragments,
  which is a different model — entries here routinely span several commits and
  most commits produce no entry at all.

  The twenty-five entries that were sitting in `[Unreleased]` are now
  twenty-five fragments. Every prose line survives byte for byte; the eight
  `###` headings that section had accumulated — `Added` twice, `Changed` twice,
  `Removed` twice, `Fixed` twice — collapse to four.
