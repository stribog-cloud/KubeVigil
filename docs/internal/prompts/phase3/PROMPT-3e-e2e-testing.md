# Phase 3e — E2E Testing: Fix Command Validation

## Context

You are continuing Phase 3 of KubeVigil. **Prompts 3a through 3d are complete.** The full fix engine is implemented:

- Foundation types, registry, YAML patcher, safety classification (3a)
- Core fixer orchestrator, backup, diff, conflict resolution (3b)
- CLI command with all flags, interactive confirmation, CI mode (3c)
- Kustomize, Helm values, fix report, verify, GitOps PR generators (3d)
- All unit and integration tests passing

**Read these files before doing ANYTHING:**
- `CLAUDE.md` — Project identity, coding standards, workflow rules
- `docs/internal/kubevigil-features-v3.md` **lines 561–935 only** (Section 7: Auto-Remediation Engine). Do NOT read the full file.
- `test/e2e/README.md` — Existing E2E test infrastructure, patterns, conventions
- `test/e2e/scenarios/` — Existing E2E scenarios (understand the patterns)
- `test/e2e/scripts/` — Existing automation scripts and Bats tests
- `cmd/kubevigil/fix.go` — Fix command from 3c

This prompt (3e) creates comprehensive **E2E tests** for the fix command, validating the full workflow from scan through fix through verification.

## Objectives

### 1. Fix-Specific E2E Scenarios

Create new scenario directories under `test/e2e/scenarios/`:

#### `test/e2e/scenarios/fix-safe/`
Manifests that ONLY trigger safe-level fixes. After `kubevigil fix --apply`:
- All findings should be resolved
- Re-scan should produce zero findings (for the fixed checks)
- Files should be valid YAML

Resources:
- Deployment with `privileged: true`
- Deployment with missing `allowPrivilegeEscalation: false`
- Deployment with `automountServiceAccountToken` not set
- Multiple containers in single pod (verify each container fixed)

#### `test/e2e/scenarios/fix-moderate/`
Manifests that trigger likely-safe fixes. Tests risk-level gating:
- `kubevigil fix --apply` → only safe fixes applied, moderate skipped
- `kubevigil fix --apply --risk-level moderate` → safe + moderate applied

Resources:
- Deployment missing `runAsNonRoot: true`
- Deployment without `readOnlyRootFilesystem: true`
- Deployment without `drop: ["ALL"]` capabilities

#### `test/e2e/scenarios/fix-aggressive/`
Manifests that trigger potentially-breaking fixes:
- `kubevigil fix --apply --risk-level moderate` → aggressive skipped
- `kubevigil fix --apply --risk-level aggressive` → all applied

Resources:
- Deployment without resource limits (fix adds default limits)
- Deployment with hostPort (fix removes it)

#### `test/e2e/scenarios/fix-system-ns/`
Manifests with resources in system namespaces. Tests hard block:
- Namespace manifest for `kube-system`
- DaemonSet in kube-system with security issues
- `kubevigil fix --apply` → system namespace resources SKIPPED
- `kubevigil fix --apply --risk-level aggressive --i-understand-system-namespaces` → included (but still classified correctly)

#### `test/e2e/scenarios/fix-known-workloads/`
Manifests with known system workloads:
- Calico node DaemonSet (needs privileged)
- CoreDNS Deployment (needs NET_BIND_SERVICE)
- Prometheus node-exporter (needs hostPID)
- Each should be detected and SKIPPED with explanatory message

#### `test/e2e/scenarios/fix-multi-doc/`
Multi-document YAML files:
- File with 3 documents: one insecure, one secure, one insecure
- Only insecure documents should be modified
- Secure document should be byte-for-byte identical after fix
- `---` separators preserved

#### `test/e2e/scenarios/fix-comments/`
YAML files with extensive comments:
- Inline comments: `privileged: true  # required for debugging`
- Head comments explaining the resource
- Block comments between sections
- After fix: ALL comments MUST be preserved (this is a critical test)

#### `test/e2e/scenarios/fix-clean/`
Fully hardened manifests (like existing `clean/` scenario):
- `kubevigil fix` → should report zero fixable findings
- Exit code 4 (nothing to do)
- No files modified, no backup created

#### `test/e2e/scenarios/fix-partial-failure/`
Mix of valid and invalid manifests to test partial failure resilience:
- Valid YAML with security issues (should be fixed)
- Malformed YAML file (should fail gracefully, not crash)
- Read-only file with security issues (should fail gracefully)
- `kubevigil fix --apply --yes` → fixes what it can, reports errors for failures
- Exit code 5 (partial success)
- Fix summary shows both applied count and error count

### 2. E2E Automation Scripts

#### `test/e2e/scripts/run-fix.sh`
Orchestrates fix E2E tests:

```bash
#!/usr/bin/env bash
# Run fix E2E tests in manifest mode

set -euo pipefail

KUBEVIGIL_BIN="${KUBEVIGIL_BIN:-bin/kubevigil}"
RESULTS_DIR="${RESULTS_DIR:-test/e2e/scan-results}"
SCENARIOS_DIR="test/e2e/scenarios"

# Test 1: Safe fixes — scan → fix → re-scan → zero findings
echo "=== Test 1: Safe fixes ==="
WORK_DIR=$(mktemp -d)
cp -r "$SCENARIOS_DIR/fix-safe/" "$WORK_DIR/"
$KUBEVIGIL_BIN fix "$WORK_DIR/fix-safe/" --apply --verify --yes 2>&1 | tee "$RESULTS_DIR/fix-safe.log"
echo "Exit code: $?"

# Verify zero findings after fix
$KUBEVIGIL_BIN scan --file "$WORK_DIR/fix-safe/" -o json > "$RESULTS_DIR/fix-safe-rescan.json"
REMAINING=$(jq '.scan_result.findings | length' "$RESULTS_DIR/fix-safe-rescan.json")
echo "Remaining findings after safe fix: $REMAINING"
# Some findings may remain (those requiring moderate/aggressive risk level)

# Test 2: Risk level gating
echo "=== Test 2: Risk level gating ==="
WORK_DIR2=$(mktemp -d)
cp -r "$SCENARIOS_DIR/fix-moderate/" "$WORK_DIR2/"
$KUBEVIGIL_BIN fix "$WORK_DIR2/fix-moderate/" --apply --yes 2>&1 | tee "$RESULTS_DIR/fix-risk-safe.log"
# Count should show moderate fixes as skipped

$KUBEVIGIL_BIN fix "$WORK_DIR2/fix-moderate/" --apply --risk-level moderate --yes 2>&1 | tee "$RESULTS_DIR/fix-risk-moderate.log"
# Now moderate fixes should be applied

# Test 3: System namespace hard block
echo "=== Test 3: System namespace protection ==="
WORK_DIR3=$(mktemp -d)
cp -r "$SCENARIOS_DIR/fix-system-ns/" "$WORK_DIR3/"
$KUBEVIGIL_BIN fix "$WORK_DIR3/fix-system-ns/" --apply --yes 2>&1 | tee "$RESULTS_DIR/fix-system-ns.log"
# System namespace resources must be SKIPPED

# Test 4: Comment preservation
echo "=== Test 4: Comment preservation ==="
WORK_DIR4=$(mktemp -d)
cp -r "$SCENARIOS_DIR/fix-comments/" "$WORK_DIR4/"
BEFORE_COMMENTS=$(grep -c '^#\|#' "$WORK_DIR4/fix-comments/"*.yaml | tail -1)
$KUBEVIGIL_BIN fix "$WORK_DIR4/fix-comments/" --apply --yes 2>&1
AFTER_COMMENTS=$(grep -c '^#\|#' "$WORK_DIR4/fix-comments/"*.yaml | tail -1)
echo "Comments before: $BEFORE_COMMENTS, after: $AFTER_COMMENTS"

# Test 5: Clean scenario — nothing to fix
echo "=== Test 5: Clean scenario ==="
$KUBEVIGIL_BIN fix "$SCENARIOS_DIR/fix-clean/" 2>&1 | tee "$RESULTS_DIR/fix-clean.log"
echo "Exit code: $?" # Should be 4

# Test 6: Backup creation
echo "=== Test 6: Backup verification ==="
# Verify backup directory was created for tests 1-4
ls -la "$WORK_DIR"/fix-safe.bak-* 2>/dev/null || echo "ERROR: No backup found"

# Test 7: Partial failure resilience
echo "=== Test 7: Partial failure ==="
WORK_DIR5=$(mktemp -d)
cp -r "$SCENARIOS_DIR/fix-partial-failure/" "$WORK_DIR5/"
# Make one file read-only to trigger a write failure
chmod 444 "$WORK_DIR5/fix-partial-failure/readonly-deployment.yaml" 2>/dev/null || true
$KUBEVIGIL_BIN fix "$WORK_DIR5/fix-partial-failure/" --apply --yes 2>&1 | tee "$RESULTS_DIR/fix-partial.log"
EXIT_CODE=$?
echo "Exit code: $EXIT_CODE"  # Should be 5 (partial success)
# Verify other files were still fixed despite the failure
grep -c "applied" "$RESULTS_DIR/fix-partial.log" || true
grep -c "error" "$RESULTS_DIR/fix-partial.log" || true

# Cleanup
rm -rf "$WORK_DIR" "$WORK_DIR2" "$WORK_DIR3" "$WORK_DIR4" "$WORK_DIR5"

echo "=== Fix E2E complete ==="
```

#### `test/e2e/scripts/run-fix-live.sh`
Fix tests against a live Kind cluster:

```bash
#!/usr/bin/env bash
# Run fix E2E tests in live cluster mode
# Tests the scan → generate kubectl patches → apply → re-scan workflow

set -euo pipefail

KUBEVIGIL_BIN="${KUBEVIGIL_BIN:-bin/kubevigil}"

# 1. Create Kind cluster
kind create cluster --config test/e2e/clusters/kind-single-node.yaml --name kubevigil-fix-e2e

# 2. Deploy insecure workloads
kubectl apply -f test/e2e/scenarios/fix-safe/

# 3. Wait for resources
sleep 10

# 4. Scan and generate kubectl patches
$KUBEVIGIL_BIN scan --namespace kv-e2e-fix-safe -o json > /tmp/pre-fix-scan.json
echo "Pre-fix findings: $(jq '.scan_result.findings | length' /tmp/pre-fix-scan.json)"

# 5. Generate kubectl patches for the manifest files
$KUBEVIGIL_BIN fix test/e2e/scenarios/fix-safe/ --output kubectl > /tmp/kubectl-patches.sh

# 6. Review patches (output for CI logs)
cat /tmp/kubectl-patches.sh

# 7. Apply patches to live cluster
bash /tmp/kubectl-patches.sh

# 8. Wait for rollout
kubectl rollout status -n kv-e2e-fix-safe --timeout=60s deployment --all

# 9. Re-scan live cluster
$KUBEVIGIL_BIN scan --namespace kv-e2e-fix-safe -o json > /tmp/post-fix-scan.json
echo "Post-fix findings: $(jq '.scan_result.findings | length' /tmp/post-fix-scan.json)"

# 10. Verify finding reduction
PRE=$(jq '.scan_result.findings | length' /tmp/pre-fix-scan.json)
POST=$(jq '.scan_result.findings | length' /tmp/post-fix-scan.json)
if [ "$POST" -ge "$PRE" ]; then
  echo "ERROR: Fix didn't reduce findings! Pre: $PRE, Post: $POST"
  exit 1
fi
echo "SUCCESS: Findings reduced from $PRE to $POST"

# 11. Cleanup
kind delete cluster --name kubevigil-fix-e2e
```

### 3. Bats Tests for Fix Scripts

Create `test/e2e/scripts/tests/fix.bats`:

```bash
#!/usr/bin/env bats

load test_helper

@test "fix dry-run produces diff output without modifying files" {
  # ...
}

@test "fix --apply modifies files and creates backup" {
  # ...
}

@test "fix --apply --verify re-scans and reports results" {
  # ...
}

@test "fix system namespace resources are skipped by default" {
  # ...
}

@test "fix --risk-level safe only applies safe fixes" {
  # ...
}

@test "fix --risk-level moderate includes likely-safe fixes" {
  # ...
}

@test "fix clean scenario reports nothing to fix with exit code 4" {
  # ...
}

@test "fix preserves YAML comments" {
  # ...
}

@test "fix multi-document YAML only modifies affected documents" {
  # ...
}

@test "fix --output kubectl generates valid kubectl commands" {
  # ...
}

@test "fix --kustomize generates valid overlay directory" {
  # ...
}

@test "fix CI mode rejects --apply without --yes" {
  # ...
}

@test "fix backup directory has correct structure" {
  # ...
}

@test "fix known workloads (calico, coredns) are detected and skipped" {
  # ...
}

@test "fix partial failure continues with remaining files and reports errors" {
  # ...
}

@test "fix partial failure returns exit code 5" {
  # ...
}

@test "fix dry-run diff includes What Could Break warnings for non-safe fixes" {
  # ...
}

@test "fix --verify exit code 0 when all fixes verified" {
  # ...
}
```

Target: **18 Bats tests** for fix-specific scenarios.

### 4. Validation Script Update

Update `test/e2e/scripts/validate-findings.py` to support fix validation:

```python
# New validation mode: fix
# Validates that:
# 1. Pre-fix scan has expected findings
# 2. Post-fix scan has fewer findings
# 3. Specific checks that were fixed produce zero findings
# 4. Files are valid YAML after fix
# 5. Backup exists

python3 test/e2e/scripts/validate-findings.py \
  --mode fix \
  --pre-scan test/e2e/scan-results/fix-safe-prescan.json \
  --post-scan test/e2e/scan-results/fix-safe-rescan.json \
  --category fix-safe
```

### 5. E2E Documentation Update

Update `test/e2e/README.md` to document:
- New fix scenarios and their purpose
- How to run fix E2E tests (manifest mode and live mode)
- Expected results per fix scenario
- Known limitations for fix E2E (system namespace tests in manifest mode, etc.)

### 6. Update Expected Findings

Add to `test/e2e/expected/README.md`:
- Expected findings per fix scenario (before fix)
- Expected remaining findings (after fix at each risk level)
- Which checks should be resolved at each risk level

## Testing Requirements

### The Golden Workflow (MUST PASS)

This is the single most important E2E test:

```
1. Start with insecure manifests (known findings)
2. kubevigil fix --apply --verify --yes → fixes applied, verify passes
3. kubevigil scan --file <path> → zero findings for fixed checks
4. YAML comments and formatting preserved
5. Backup directory exists with originals
```

If this workflow breaks, Phase 3 is not shippable.

### Specific Validations

| Test | Assertion |
|------|-----------|
| Safe fix | All safe-classified findings resolved after fix |
| Risk gating | moderate/aggressive findings skipped at safe risk level |
| System NS block | kube-system resources never modified without explicit flag |
| Known workloads | Calico, CoreDNS, node-exporter identified and skipped |
| Comment preservation | Comment count before == comment count after |
| Multi-doc | Only insecure documents modified, secure ones byte-identical |
| Backup | Backup dir exists, originals match pre-fix state |
| Clean scenario | Exit code 4, no files modified, no backup |
| kubectl output | Generated commands are syntactically valid |
| Kustomize output | Generated overlay directory is valid (kustomize build succeeds) |
| Verify pass | --verify after successful fix → exit code 0 |
| CI mode | --apply without --yes in CI env → exit code 3 |
| Partial failure | Malformed/read-only files don't crash; fixed files still patched, errors reported, exit code 5 |
| Inline warnings | Dry-run diff includes "What Could Break" for likely_safe and potentially_breaking fixes |

## Tasks Integration

File issues:
- `phase3-e2e-fix-scenarios` — Create all fix E2E scenario manifests
- `phase3-e2e-fix-scripts` — run-fix.sh and run-fix-live.sh
- `phase3-e2e-fix-bats` — Bats test file for fix
- `phase3-e2e-validation-update` — Update validate-findings.py for fix mode
- `phase3-e2e-docs-update` — Update E2E README and expected findings

## Quality Gates

1. All Bats tests pass: `bats test/e2e/scripts/tests/fix.bats`
2. Manifest-mode fix E2E passes: `./test/e2e/scripts/run-fix.sh`
3. Live-mode fix E2E passes: `./test/e2e/scripts/run-fix-live.sh` (requires Kind)
4. Golden workflow verified end-to-end
5. All existing E2E tests still pass (no regressions)
6. `go test ./...` passes
7. Tasks issues filed and updated
8. `git push` to remote

## Files Created/Modified

### New Files
- `test/e2e/scenarios/fix-safe/*.yaml`
- `test/e2e/scenarios/fix-moderate/*.yaml`
- `test/e2e/scenarios/fix-aggressive/*.yaml`
- `test/e2e/scenarios/fix-system-ns/*.yaml`
- `test/e2e/scenarios/fix-known-workloads/*.yaml`
- `test/e2e/scenarios/fix-multi-doc/*.yaml`
- `test/e2e/scenarios/fix-comments/*.yaml`
- `test/e2e/scenarios/fix-clean/*.yaml`
- `test/e2e/scenarios/fix-partial-failure/*.yaml`
- `test/e2e/scripts/run-fix.sh`
- `test/e2e/scripts/run-fix-live.sh`
- `test/e2e/scripts/tests/fix.bats`

### Modified Files
- `test/e2e/scripts/validate-findings.py` — Add fix validation mode
- `test/e2e/README.md` — Document fix E2E tests
- `test/e2e/expected/README.md` — Add fix scenario expected findings
