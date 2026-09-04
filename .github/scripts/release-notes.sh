#!/usr/bin/env bash
# Print the CHANGELOG section for one tag, as the release body.
#
#   .github/scripts/release-notes.sh v0.2.3 [CHANGELOG.md]
#
# The notes are never written by hand at release time: they are the section that already
# exists in CHANGELOG.md, so the release page and the file cannot drift. A tag with no
# section is an error, not an empty release body — a release that says nothing is worse
# than a build that stops and asks.
set -euo pipefail

tag="${1:-}"
changelog="${2:-CHANGELOG.md}"

if [ -z "$tag" ]; then
  echo "usage: ${0##*/} <tag> [changelog]" >&2
  exit 2
fi
if [ ! -f "$changelog" ]; then
  echo "error: $changelog not found" >&2
  exit 2
fi

version="${tag#v}"

# Keep-a-Changelog headings: `## [0.2.3] - 2026-09-04`. Take everything up to the next `## [`
# heading, so `### Security` and friends come along. The oldest section has no heading after
# it, only the link-reference block at the foot of the file — stop there too, or the oldest
# release ships a list of URLs as its notes.
section="$(
  awk -v version="$version" '
    index($0, "## [" version "]") == 1 { inside = 1; next }
    inside && index($0, "## [") == 1   { exit }
    inside && /^\[[^]]+\]: /           { exit }
    inside                             { print }
  ' "$changelog"
)"

# Trim the blank lines the section boundaries leave at both ends.
section="$(printf '%s\n' "$section" | sed -e '/./,$!d' | tac | sed -e '/./,$!d' | tac)"

if [ -z "$section" ]; then
  echo "error: no CHANGELOG section for $tag (looked for '## [$version]' in $changelog)" >&2
  echo "hint: add the section before tagging; an empty release body is a broken release." >&2
  exit 1
fi

printf '%s\n' "$section"
