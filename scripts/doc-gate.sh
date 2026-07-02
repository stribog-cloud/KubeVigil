#!/usr/bin/env bash
# Doc-to-release sync gate (User Documentation Standard §11).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() { echo "doc-gate: $*" >&2; exit 1; }

[[ -f CHANGELOG.md ]] || fail "CHANGELOG.md missing"
[[ -f docs/user/releases/README.md ]] || fail "docs/user/releases/README.md missing"
[[ -f docs/governance/Charter-Compliance-Annex.md ]] || fail "Charter Compliance Annex missing"

# Latest changelog section must mention current minor line (0.5.x)
grep -q '## \[0\.5\.' CHANGELOG.md || fail "CHANGELOG missing 0.5.x release section"

# User release notes index must reference the same line
grep -q '0\.5' docs/user/releases/README.md || fail "user release notes missing 0.5.x entry"

echo "doc-gate: OK"