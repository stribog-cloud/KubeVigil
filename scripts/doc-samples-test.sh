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

# fix dry-run on a documented fixture (no --apply; must not modify files).
FIXTURE="$ROOT/test/fixtures/fix/simple-deployment.yaml"
[[ -f "$FIXTURE" ]] || fail "fix fixture missing: $FIXTURE"
FIX_HASH_BEFORE=$(shasum -a 256 "$FIXTURE" | awk '{print $1}')
"$BIN" fix "$FIXTURE" >/dev/null || fail "fix dry-run failed"
FIX_HASH_AFTER=$(shasum -a 256 "$FIXTURE" | awk '{print $1}')
if [ "$FIX_HASH_BEFORE" != "$FIX_HASH_AFTER" ]; then
  fail "fix dry-run modified fixture (expected no writes without --apply)"
fi

# Documented fix flags must remain wired (cli-reference.md).
"$BIN" fix "$FIXTURE" --risk-level moderate >/dev/null || fail "fix --risk-level moderate failed"
"$BIN" fix "$FIXTURE" -o diff >/dev/null || fail "fix -o diff failed"

# --apply on scratch copy (documented in quickstart / auto-fix overview).
SCRATCH=$(mktemp -d)
trap 'rm -rf "$SCRATCH"' EXIT
cp "$FIXTURE" "$SCRATCH/simple-deployment.yaml"
SCRATCH_FILE="$SCRATCH/simple-deployment.yaml"
SCRATCH_HASH_BEFORE=$(shasum -a 256 "$SCRATCH_FILE" | awk '{print $1}')
"$BIN" fix "$SCRATCH_FILE" --apply --yes >/dev/null || fail "fix --apply --yes on scratch copy failed"
SCRATCH_HASH_AFTER=$(shasum -a 256 "$SCRATCH_FILE" | awk '{print $1}')
if [ "$SCRATCH_HASH_BEFORE" = "$SCRATCH_HASH_AFTER" ]; then
  fail "fix --apply --yes did not modify scratch copy"
fi

# Contributor architecture doc: contract test name must match a real test.
go test ./test/integration/ -run TestAllCheckersContract -count=1 >/dev/null || \
  fail "TestAllCheckersContract integration test failed"

echo "doc-samples-test: OK"