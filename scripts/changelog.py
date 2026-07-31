#!/usr/bin/env python3
"""Assemble CHANGELOG.md from one-file-per-change fragments in changelog.d/.

The `[Unreleased]` section of a changelog is the one file every branch in
flight appends to, which makes it a structural conflict generator rather than
anyone's carelessness: two branches that touch no common source file still
collide there. A conflicted CHANGELOG.md once reached main because nothing in
the pipeline reads prose. Removing the shared write target removes the class.

A fragment is a plain Markdown file whose name carries the category and whose
body is one changelog bullet, copied into the release section byte for byte:

    changelog.d/fixed-sensitive-pattern-in-detail.md

        - **A per-host sensitive pattern no longer appears in the detail.**
          The detail read `Sensitive pattern '<the pattern>' found in ...`
          and it is persisted to `security_events`, so the check re-leaked
          exactly what it exists to stop.

Commands
--------
    scripts/changelog.py check                 validate every fragment
    scripts/changelog.py render                print the assembled section
    scripts/changelog.py release 0.2.215       splice it in, delete fragments

`check` runs in CI. `render` and `release` run on the operator's machine at
step 3 of docs/RELEASING.md, before the tag exists -- an assembly that cannot
be produced fails on a terminal rather than half way through a six-job release
pipeline, which is why nothing here is wired into release.yml.
"""

from __future__ import annotations

import argparse
import datetime
import re
import subprocess
import sys
from pathlib import Path

# Filename prefix -> heading, in the order the headings are emitted. Security
# leads because it is the section an operator greps to decide whether to page
# someone, and Breaking Changes trails because it is what they read last,
# after they have accepted the upgrade. The rest is Keep a Changelog order.
CATEGORIES: dict[str, str] = {
    "security": "Security",
    "added": "Added",
    "changed": "Changed",
    "deprecated": "Deprecated",
    "removed": "Removed",
    "fixed": "Fixed",
    "breaking": "Breaking Changes",
}

# <category>-<slug>.md. The slug is lowercase words joined by hyphens; it names
# the change for a reader of `ls changelog.d/` and is otherwise inert. There is
# deliberately no issue number in it: this changelog has never cited one.
FRAGMENT_NAME = re.compile(
    r"^(?P<category>" + "|".join(CATEGORIES) + r")-(?P<slug>[a-z0-9]+(?:-[a-z0-9]+)*)\.md$"
)

RESERVED_NAMES = {"README.md"}

REPO_ROOT = Path(__file__).resolve().parent.parent
FRAGMENT_DIR = REPO_ROOT / "changelog.d"
CHANGELOG = REPO_ROOT / "CHANGELOG.md"

UNRELEASED_HEADING = "## [Unreleased]"
VERSION_HEADING = re.compile(r"^## \[")


class FragmentError(Exception):
    """A fragment that cannot be rendered. Raised with a human-facing list."""

    def __init__(self, problems: list[str]) -> None:
        super().__init__("\n".join(problems))
        self.problems = problems


def load_fragments() -> list[tuple[str, str, str]]:
    """Return (category, name, body) sorted by category order then filename.

    Every fragment is validated; all problems are reported at once so that a
    contributor fixes one round of them rather than one per run.
    """
    if not FRAGMENT_DIR.is_dir():
        raise FragmentError([f"{FRAGMENT_DIR} does not exist"])

    problems: list[str] = []
    found: list[tuple[str, str, str]] = []

    for path in sorted(FRAGMENT_DIR.iterdir()):
        if path.name in RESERVED_NAMES or path.name.startswith("."):
            continue
        if not path.is_file():
            problems.append(f"{path.name}: not a file")
            continue

        match = FRAGMENT_NAME.match(path.name)
        if match is None:
            problems.append(
                f"{path.name}: name must be <category>-<slug>.md with category "
                f"one of {', '.join(CATEGORIES)}, and slug lowercase words "
                f"joined by hyphens"
            )
            continue

        body = path.read_text(encoding="utf-8").strip("\n")
        problems.extend(f"{path.name}: {p}" for p in validate_body(body))
        found.append((match.group("category"), path.name, body))

    if problems:
        raise FragmentError(problems)

    order = list(CATEGORIES)
    found.sort(key=lambda item: (order.index(item[0]), item[1]))
    return found


def validate_body(body: str) -> list[str]:
    """Check that a fragment body is exactly one well-formed Markdown bullet."""
    problems: list[str] = []
    lines = body.split("\n")

    if not body.strip():
        return ["file is empty"]
    if not lines[0].startswith("- "):
        return ["must begin with a top-level Markdown bullet, `- `"]

    for number, line in enumerate(lines[1:], start=2):
        if not line.strip():
            continue
        if line.startswith("- "):
            problems.append(
                f"line {number}: a second top-level bullet. One change per "
                f"file is the point -- split it, or indent this line by two "
                f"spaces to keep it inside the first bullet"
            )
        elif not line.startswith("  "):
            problems.append(
                f"line {number}: continuation lines belong to the bullet and "
                f"must be indented by two spaces"
            )
        elif line.rstrip() != line:
            problems.append(f"line {number}: trailing whitespace")

    return problems


def render(fragments: list[tuple[str, str, str]]) -> str:
    """Concatenate fragments into Keep a Changelog subsections, verbatim.

    Nothing is rewrapped or reformatted. The entries in this changelog are
    hand-set paragraphs where the line breaks carry emphasis, and a tool that
    reflows them would quietly rewrite prose that was argued over.
    """
    blocks: list[str] = []
    current: str | None = None

    for category, _name, body in fragments:
        if category != current:
            blocks.append(f"### {CATEGORIES[category]}")
            current = category
        blocks.append(body)

    return "\n\n".join(blocks) + "\n"


def splice(version: str, date: str, section: str) -> str:
    """Insert a new version section between `[Unreleased]` and its predecessor.

    `[Unreleased]` keeps its heading and its pointer to changelog.d/, because
    that text is static and is therefore not something two branches can
    conflict over.
    """
    text = CHANGELOG.read_text(encoding="utf-8")
    lines = text.split("\n")

    try:
        start = next(i for i, line in enumerate(lines) if line.strip() == UNRELEASED_HEADING)
    except StopIteration:
        raise FragmentError([f"no `{UNRELEASED_HEADING}` heading in CHANGELOG.md"]) from None

    heading = f"## [{version}]"
    if any(line.startswith(heading) for line in lines):
        raise FragmentError([f"CHANGELOG.md already has a `{heading}` section"])

    try:
        insert_at = next(
            i for i, line in enumerate(lines[start + 1 :], start=start + 1) if VERSION_HEADING.match(line)
        )
    except StopIteration:
        insert_at = len(lines)

    new = [f"## [{version}] — {date}", "", section.rstrip("\n"), "", "---", ""]
    return "\n".join(lines[:insert_at] + new + lines[insert_at:])


def remove_consumed(paths: list[Path]) -> None:
    """Delete consumed fragments and stage the deletions, via `git rm`.

    Staging matters: a release commit that ships the assembled section while
    leaving the fragments on disk would emit every one of them again next time.

    `git rm` rather than unlink-then-add, because it refuses on a fragment git
    does not already know about. That refusal is the point. An unlink deletes an
    uncommitted fragment with no way back — which is exactly what happened the
    first time this command was run — whereas `git rm` stops and says so, and
    the fix is to commit the fragment. Release is cut from a clean tree anyway.
    """
    try:
        subprocess.run(
            ["git", "rm", "--quiet", "--"] + [str(p) for p in paths],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        raise FragmentError(
            [
                "CHANGELOG.md is written, but the fragments could not be "
                "removed, so they would be published twice:",
                (exc.stderr or "").strip(),
                "Commit the fragments, revert CHANGELOG.md, and run this again.",
            ]
        ) from None
    except OSError as exc:
        raise FragmentError([f"could not run git: {exc}"]) from None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", maxsplit=1)[0])
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("check", help="validate every fragment in changelog.d/")
    sub.add_parser("render", help="print the assembled section to stdout")

    release = sub.add_parser("release", help="splice the section into CHANGELOG.md")
    release.add_argument("version", help="the version being released, without a leading v")
    release.add_argument("--date", default=None, help="release date, default today (UTC)")

    args = parser.parse_args()

    try:
        fragments = load_fragments()
    except FragmentError as exc:
        print("error: changelog.d/ does not validate\n", file=sys.stderr)
        for problem in exc.problems:
            print(f"  {problem}", file=sys.stderr)
        return 1

    if args.command == "check":
        counts: dict[str, int] = {}
        for category, _name, _body in fragments:
            counts[category] = counts.get(category, 0) + 1
        summary = ", ".join(f"{n} {c}" for c, n in counts.items()) or "none"
        print(f"changelog.d: {len(fragments)} fragment(s) ({summary})")
        return 0

    if not fragments:
        print(
            "error: changelog.d/ holds no fragments, so there is nothing to "
            "assemble. A release with no changelog entry is a release nobody "
            "can read.",
            file=sys.stderr,
        )
        return 1

    section = render(fragments)

    if args.command == "render":
        sys.stdout.write(section)
        return 0

    date = args.date or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    try:
        updated = splice(args.version, date, section)
    except FragmentError as exc:
        for problem in exc.problems:
            print(f"error: {problem}", file=sys.stderr)
        return 1

    CHANGELOG.write_text(updated, encoding="utf-8")
    try:
        remove_consumed([FRAGMENT_DIR / name for _category, name, _body in fragments])
    except FragmentError as exc:
        for problem in exc.problems:
            print(f"error: {problem}", file=sys.stderr)
        return 1
    print(
        f"CHANGELOG.md: added `## [{args.version}] — {date}` from "
        f"{len(fragments)} fragment(s); the fragments are deleted and staged."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
