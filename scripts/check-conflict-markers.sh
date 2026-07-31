#!/usr/bin/env bash
#
# Fail if any tracked file carries an unresolved merge conflict marker.
#
# A CHANGELOG.md holding eighty lines of conflict markers once reached main.
# Seven self-check gates ran on that commit and all seven passed, because
# fmt, clippy, check, machete, test, audit and deny between them read Rust
# source and Cargo metadata and nothing else. Prose is unguarded, and prose is
# exactly where parallel branches collide. This reads every tracked file.
#
# Detection is on the angle markers only. Git writes all three of
# `<`x7, `=`x7 and `>`x7 for every conflict it leaves behind (plus `|`x7 for
# the common ancestor under diff3/zdiff3), so keying on the angles loses
# nothing, while a bare seven-equals line is ordinary content: a setext
# heading underline, an ASCII rule in a Python docstring, a table separator.
# This repository has seven such lines today and none of them is a conflict.
# Requiring the angles keeps the check at zero false positives, which is the
# only state in which anyone still reads its output.
#
# Once a file is implicated, every marker line in it is printed, separators
# included, so the reader sees the extent of the damage rather than one line
# of it.
#
# Usage: scripts/check-conflict-markers.sh
# Exits 0 when clean, 1 when a marker is found, 2 on a usage error.

set -euo pipefail

if ! root="$(git rev-parse --show-toplevel 2>/dev/null)"; then
	echo "error: not inside a git repository" >&2
	exit 2
fi
cd "$root"

# Seven characters and then a label or the end of the line. `{7}` is exact:
# `={7,}` would drag in the long ASCII rules this repository already has, and
# a conflict marker is never longer than seven.
angle_markers='^(<{7}|\|{7}|>{7})( |$)'
all_markers='^(<{7}|\|{7}|={7}|>{7})( |$)'

# -I skips binary files, -l lists names. A miss makes git grep exit 1, which
# under `set -e` would end the script, so the failure is absorbed here and the
# emptiness of the result is what gets tested.
implicated="$(git grep -I -l -E "$angle_markers" -- . || true)"

if [ -z "$implicated" ]; then
	echo "conflict markers: none in $(git ls-files | wc -l) tracked files"
	exit 0
fi

echo "error: unresolved merge conflict markers are committed" >&2
echo >&2
while IFS= read -r file; do
	[ -n "$file" ] || continue
	git grep -I -n -E "$all_markers" -- "$file" >&2 || true
	echo >&2
done <<<"$implicated"

cat >&2 <<'EOF'
Resolve the conflict, delete the markers, and commit again.
This check is the first job in CI so that it fails in seconds rather than
after a thirty-minute build. Run it locally with:

    scripts/check-conflict-markers.sh
EOF

exit 1
