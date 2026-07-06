#!/usr/bin/env bash
# Per-package coverage gate for critical-path packages (Charter §5.4).
#
# Runs `go test -cover` for each given package individually and fails if any
# package's statement coverage is below the floor. This is stricter than the
# blended `make coverage` gate, which can hide a weak package behind strong
# ones elsewhere in the module.
#
# Usage:
#   scripts/coverage-pkg.sh [floor] [package...]
#
#   floor    - minimum required coverage percent (default: 96)
#   package  - one or more package paths relative to the module root
#              (default: internal/fix internal/mcp internal/checker/secrets)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() { echo "coverage-pkg: $*" >&2; exit 1; }

FLOOR="${1:-96}"
if [[ $# -gt 0 ]]; then
  shift
fi

if [[ $# -eq 0 ]]; then
  set -- internal/fix internal/mcp internal/checker/secrets
fi

# Validate floor is numeric before using it in awk comparisons.
[[ "$FLOOR" =~ ^[0-9]+(\.[0-9]+)?$ ]] || fail "invalid floor value: $FLOOR"

status=0
echo "coverage-pkg: enforcing >= ${FLOOR}% statement coverage per package"

for pkg in "$@"; do
  [[ -d "$pkg" ]] || fail "package directory not found: $pkg"

  output="$(go test -cover -count=1 "./${pkg}/" 2>&1)" || {
    echo "$output" >&2
    echo "coverage-pkg: FAIL ${pkg} — go test failed" >&2
    status=1
    continue
  }

  # Match a line like: "ok  	module/path	1.2s	coverage: 96.6% of statements"
  # awk parsing is robust to varying whitespace and trailing text after '%'.
  pct="$(printf '%s\n' "$output" | awk -F'coverage: ' '/coverage:/ { split($2, a, "%"); print a[1]; exit }')"

  if [[ -z "$pct" ]]; then
    echo "$output" >&2
    fail "could not parse coverage percentage for ${pkg}"
  fi

  if awk -v p="$pct" -v f="$FLOOR" 'BEGIN { exit !(p + 0 >= f + 0) }'; then
    echo "coverage-pkg: PASS ${pkg} (${pct}% >= ${FLOOR}%)"
  else
    echo "coverage-pkg: FAIL ${pkg} (${pct}% < ${FLOOR}%)" >&2
    status=1
  fi
done

if [[ "$status" -ne 0 ]]; then
  fail "one or more packages are below the ${FLOOR}% per-package coverage floor"
fi

echo "coverage-pkg: all packages meet the ${FLOOR}% floor"
