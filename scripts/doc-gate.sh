#!/usr/bin/env bash
# Doc-to-release sync gate (User Documentation Standard §11).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() { echo "doc-gate: $*" >&2; exit 1; }

[[ -f CHANGELOG.md ]] || fail "CHANGELOG.md missing"
[[ -f docs/user/releases/README.md ]] || fail "docs/user/releases/README.md missing"
[[ -f docs/governance/Charter-Compliance-Annex.md ]] || fail "Charter Compliance Annex missing"

# Authoritative released version from newest STABLE semver git tag (not
# doc-vs-doc cross-check). Prerelease tags (e.g. v1.0.0-rc.1, v1.0.0-alpha)
# are excluded -- release docs track the latest stable release, not an rc.
LATEST_TAG=$(git tag -l 'v[0-9]*' --sort=-v:refname 2>/dev/null | grep -vE -- '-' | head -1 || true)
[[ -n "$LATEST_TAG" ]] || fail "no stable release tag found (git tag -l)"
TAG_VER=${LATEST_TAG#v}
grep -qE "## \\[${TAG_VER//./\\.}\\]" CHANGELOG.md || \
  fail "CHANGELOG missing section for tag ${LATEST_TAG} (authoritative version ${TAG_VER})"
grep -q "${TAG_VER}" docs/user/releases/README.md || \
  fail "user release notes missing authoritative version ${TAG_VER} from ${LATEST_TAG}"

# Frontmatter status must use Stribog vocabulary (Documentation Standard §10.1)
VALID_STATUSES='draft-scaffold|review-draft|design-reference|governing-reference|frozen-reference|superseded|archived'
for f in docs/dev/*.md docs/user/*.md docs/user/releases/*.md docs/governance/*.md docs/governance/adr/*.md; do
  [[ -f "$f" ]] || continue
  status=$(sed -n '/^---$/,/^---$/p' "$f" | sed -n 's/^status:[[:space:]]*\(.*\)/\1/p' | head -1)
  if [[ -n "$status" ]] && ! echo "$status" | grep -qE "^(${VALID_STATUSES})$"; then
    fail "invalid status '$status' in $f"
  fi
done

echo "doc-gate: OK"