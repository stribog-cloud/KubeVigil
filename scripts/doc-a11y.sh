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

# Images must have non-empty alt text (reject ![](path) and ![ ](path))
bad_alt=$(grep -rE '!\[\]\([^)]+\)|!\[[[:space:]]*\]\([^)]+\)' docs/ --include='*.md' 2>/dev/null || true)
if [[ -n "$bad_alt" ]]; then
  echo "$bad_alt" >&2
  fail "found markdown images without alt text"
fi

echo "doc-a11y: OK"