#!/usr/bin/env bash
# Smoke-test documented commands (Developer Documentation Standard — code samples).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() { echo "doc-samples-test: $*" >&2; exit 1; }

make build >/dev/null
BIN="$ROOT/bin/kubevigil"

"$BIN" version >/dev/null || fail "version command failed"
"$BIN" list checks >/dev/null || fail "list checks failed"
set +e
"$BIN" scan -f test/fixtures/privileged/pod-privileged-true.yaml -o text >/dev/null 2>&1
rc=$?
set -e
# Exit 0 = clean scan; exit 1 = findings present (expected for this fixture).
if [ "$rc" -ne 0 ] && [ "$rc" -ne 1 ]; then
  fail "scan fixture failed (exit $rc)"
fi

echo "doc-samples-test: OK"