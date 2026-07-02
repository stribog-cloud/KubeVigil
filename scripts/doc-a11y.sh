#!/usr/bin/env bash
# Markdown structure check for user docs (headings, alt text placeholders).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() { echo "doc-a11y: $*" >&2; exit 1; }

for f in docs/getting-started/quickstart.md docs/user/support.md docs/index.md; do
  [[ -f "$f" ]] || fail "missing $f"
  grep -q '^#' "$f" || fail "$f has no headings"
done

# Images in docs should declare alt text when present
while IFS= read -r -d '' img; do
  if ! grep -B1 -F "$img" "${img%.md}.md" 2>/dev/null | grep -q '!\['; then
    : # skip — checked via rg below
  fi
done < /dev/null

if rg '!\[\]\(' docs/ >/dev/null 2>&1; then
  fail "found markdown images without alt text"
fi

echo "doc-a11y: OK"