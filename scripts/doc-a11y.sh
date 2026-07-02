#!/usr/bin/env bash
# Markdown structure check for user docs (headings, alt text).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() { echo "doc-a11y: $*" >&2; exit 1; }

for f in docs/getting-started/quickstart.md docs/user/support.md docs/index.md; do
  [[ -f "$f" ]] || fail "missing $f"
  grep -q '^#' "$f" || fail "$f has no headings"
done

# Strip fenced code blocks and inline-code spans before scanning prose for image alt text.
# This avoids false positives from documented examples (e.g. mutation-test tables).
scan_prose() {
  awk '
    BEGIN { in_fence = 0 }
    /^```/ { in_fence = !in_fence; next }
    in_fence { next }
    {
      line = $0
      while (match(line, /`[^`]*`/)) {
        sub(/`[^`]*`/, "", line)
      }
      print line
    }
  '
}

bad_alt=$(
  find docs -name '*.md' -print0 |
    xargs -0 cat |
    scan_prose |
    grep -E '!\[\]\([^)]+\)|!\[[[:space:]]*\]\([^)]+\)' || true
)
if [[ -n "$bad_alt" ]]; then
  echo "$bad_alt" >&2
  fail "found markdown images without alt text"
fi

echo "doc-a11y: OK"