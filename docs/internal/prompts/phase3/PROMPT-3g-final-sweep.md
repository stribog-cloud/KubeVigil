# PROMPT — Phase 3 Final Sweep (Verification & Quality Gate)

> **Purpose:** This is NOT a build prompt. This is a verification prompt. You are auditing the completed Phase 3 implementation to catch gaps, regressions, inconsistencies, and loose ends before Phase 3 is declared shippable. You should FIX any issues you find, but the primary goal is detection.

---

## Pre-Flight

**Read these files before doing ANYTHING:**

- `CLAUDE.md` — Current project state (should reflect Phase 3 complete)
- `docs/internal/kubevigil-features-v3.md` **lines 561–935 only** (Section 7: Auto-Remediation Engine)
- `docs/internal/prompts/phase3/README.md` — Expected deliverables inventory

---

## Sweep 1: File Inventory Verification

Compare what EXISTS on disk against what was SPECIFIED in the prompts. Run these checks:

```bash
# Expected files in internal/fix/
EXPECTED=(
  types.go types_test.go
  registry.go registry_test.go
  yaml_patcher.go yaml_patcher_test.go
  safety.go safety_test.go
  known_workloads.go known_workloads_test.go
  fixer.go fixer_test.go
  backup.go backup_test.go
  diff.go diff_test.go
  report.go report_test.go
  kubectl_gen.go kubectl_gen_test.go
  kustomize_gen.go kustomize_gen_test.go
  helm_gen.go helm_gen_test.go
  gitops.go gitops_test.go
)

for f in "${EXPECTED[@]}"; do
  [ -f "internal/fix/$f" ] || echo "MISSING: internal/fix/$f"
done

# Expected CLI files
[ -f "cmd/kubevigil/fix.go" ] || echo "MISSING: cmd/kubevigil/fix.go"
[ -f "cmd/kubevigil/fix_test.go" ] || echo "MISSING: cmd/kubevigil/fix_test.go"

# Expected E2E scenarios (9 directories)
for d in fix-safe fix-moderate fix-aggressive fix-system-ns fix-known-workloads fix-multi-doc fix-comments fix-partial-failure fix-clean; do
  [ -d "test/e2e/scenarios/$d" ] || echo "MISSING SCENARIO: test/e2e/scenarios/$d"
  # Each scenario should have at least one YAML file
  count=$(find "test/e2e/scenarios/$d" -name "*.yaml" -o -name "*.yml" 2>/dev/null | wc -l)
  [ "$count" -gt 0 ] || echo "EMPTY SCENARIO (no YAML): test/e2e/scenarios/$d"
done

# Expected E2E scripts
[ -f "test/e2e/scripts/run-fix.sh" ] || echo "MISSING: test/e2e/scripts/run-fix.sh"
[ -f "test/e2e/scripts/run-fix-live.sh" ] || echo "MISSING: test/e2e/scripts/run-fix-live.sh"
[ -f "test/e2e/scripts/tests/fix.bats" ] || echo "MISSING: test/e2e/scripts/tests/fix.bats"
```

**Any file listed as MISSING or EMPTY must be investigated.** If a file was intentionally merged into another (e.g., kubectl generation folded into fixer.go), document the deviation. If it was simply forgotten, create a Tasks issue.

Also check for UNEXPECTED files — anything in `internal/fix/` that wasn't planned (e.g., `detect.go`). These aren't necessarily wrong, but document what they do and confirm they have tests.

---

## Sweep 2: Test Health

### 2a. All Tests Pass

```bash
go test ./... 2>&1
```

**Zero failures tolerated.** If anything fails, fix it before proceeding.

### 2b. Fix Package Coverage

```bash
go test ./internal/fix/... -coverprofile=coverage-fix.out
go tool cover -func=coverage-fix.out | tail -1    # Total coverage
go tool cover -func=coverage-fix.out | sort -t: -k3 -n | head -20  # Lowest-covered functions
```

**Target: ≥ 85% line coverage for `internal/fix/` package.** If below 85%, identify which functions are uncovered and assess:
- Is it a code path that SHOULD be tested? → File a Tasks issue or fix now.
- Is it an error path that's hard to trigger in unit tests? → Acceptable if covered by E2E.

### 2c. Fix Command Coverage

```bash
go test ./cmd/kubevigil/... -coverprofile=coverage-cmd.out -run TestFix
go tool cover -func=coverage-cmd.out | grep fix
```

### 2d. Phase 1/2 Regression Check

```bash
# Run ALL tests, not just fix
go test ./internal/checker/... -count=1
go test ./internal/engine/... -count=1
go test ./internal/report/... -count=1
go test ./internal/config/... -count=1
go test ./internal/frameworks/... -count=1
go test ./test/integration/... -count=1
```

**Every pre-existing test MUST still pass.** The Finding struct extension (CurrentValue, DesiredValue, FixHint) was backward-compatible — if any Phase 1/2 test broke, something went wrong in 3a or 3f.

### 2e. Contract Test Verification

```bash
go test ./test/integration/... -run TestContract -v
```

Confirm the contract test still iterates ALL registered checkers and passes. The count should be 110 (or whatever the current total is).

---

## Sweep 3: FixHint Backfill Verification

3f was supposed to backfill 20 checkers with FixHint data. Verify:

```bash
# Search for FixHint population in checker files
grep -rn "FixHint" internal/checker/ --include="*.go" | grep -v "_test.go" | grep -v "FixHint.*\*fix\." | grep -v "// "
```

Cross-reference against the expected list:

**Safe (7):** privileged, privilege-escalation, host-pid, host-ipc, proc-mount, share-process-namespace, automount-token

**Likely Safe (9):** capabilities-added, capabilities-not-dropped, run-as-root (2 paths), read-only-rootfs, host-network, seccomp-profile, image-pull-policy, psa-labels-missing, psa-mode-audit-only

**Potentially Breaking (4):** resource-limits-missing, resource-requests-missing, ephemeral-storage-limits, host-ports

For EACH of these 20 checkers, verify:
1. `CurrentValue` is populated (not always nil)
2. `DesiredValue` is populated with the correct secure value
3. `FixHint.Safety` matches the classification above
4. `FixHint.Operation` is correct (set vs add vs remove)
5. `FixHint.Impact` is a non-empty string explaining what could break

**Spot-check at least 5 checkers by reading the actual code** — don't just grep. Verify the values make sense.

---

## Sweep 4: Safety Model Verification

### 4a. System Namespace Hard Block

Read `internal/fix/safety.go` and verify:
- The default system namespace list contains AT LEAST: kube-system, kube-public, kube-node-lease, calico-system, tigera-operator, cilium, rook-ceph, longhorn-system, monitoring, cert-manager, ingress-nginx, istio-system, linkerd, metallb-system, external-dns, external-secrets, argocd, flux-system, velero, gatekeeper-system
- The `--i-understand-system-namespaces` flag is the ONLY way to bypass
- Config `additionalSystemNamespaces` is ADDITIVE (test exists proving you can't remove built-in namespaces)

### 4b. Risk Level Gating

Read `internal/fix/fixer.go` or the relevant gating logic and verify:
- Default (no risk flag) = Safe only
- `--risk-level moderate` = Safe + Likely Safe
- `--risk-level aggressive` = Safe + Likely Safe + Potentially Breaking
- Manual Only fixes are NEVER applied regardless of risk level
- Tests exist for each gating boundary

### 4c. Known Workload Detection

Read `internal/fix/known_workloads.go` and verify:
- Calico, Cilium, Flannel CNI patterns detected
- Rook-Ceph, Longhorn storage operators detected
- Prometheus node-exporter detected
- CoreDNS, kube-proxy detected
- Detection is by image name pattern AND/OR well-known labels
- A test proves known workloads are skipped during fix

### 4d. Dry-Run Default

Read `cmd/kubevigil/fix.go` and verify:
- Running `kubevigil fix <path>` without `--apply` produces diff output and exits WITHOUT modifying any files
- There is a test proving no file modification without `--apply`

---

## Sweep 5: YAML Round-Trip Integrity

This is the highest-risk component. Read `internal/fix/yaml_patcher.go` and its tests:

### 5a. Comment Preservation
- Verify a test exists that parses YAML with inline comments, applies a fix, and asserts comments survive
- Verify head comments (above a key) survive
- Verify foot comments (below a section) survive

### 5b. Key Ordering
- Verify a test exists that asserts key order is preserved after patching (not alphabetically reordered)

### 5c. Indentation Style
- Verify the patcher preserves original indentation (2-space, 4-space) rather than imposing its own

### 5d. Multi-Document YAML
- Verify a test exists for `---` separated documents where only one document is modified and others are byte-for-byte identical

### 5e. Quoting Style
- Verify quoted strings (`"value"` vs `value` vs `'value'`) are preserved

If ANY of the above tests are missing, create them. These are the most likely source of production bugs.

---

## Sweep 6: CLI Completeness

### 6a. Flag Inventory

Read `cmd/kubevigil/fix.go` and verify ALL these flags exist:
- `--apply` (bool, default false)
- `--risk-level` (string: safe/moderate/aggressive, default safe)
- `--checks` (string slice)
- `--severity` (string slice)
- `--namespace` (string slice)
- `--exclude-namespace` (string slice)
- `--exclude-infra` (bool)
- `--fingerprint` (string slice)
- `--yes` (bool, default false)
- `--output` (string: kubectl/helm-values)
- `--kustomize` (string, directory path)
- `--verify` (bool)
- `--report` (string, file path)
- `--git-pr` (bool)
- `--backup-dir` (string)
- `--i-understand-system-namespaces` (bool)

Any missing flag = Tasks issue.

### 6b. Exit Codes

Verify the fix command returns the correct exit codes. Check for tests covering:
- Exit 0: successful fix or dry-run with changes
- Exit 1: fix applied but --verify found remaining findings
- Exit 2: total failure
- Exit 3: config error (bad flags)
- Exit 4: nothing to fix
- Exit 5: partial success (some files failed)

### 6c. Help Text

```bash
go run ./cmd/kubevigil fix --help
```

Verify the help text is clear, lists all flags, and includes usage examples.

---

## Sweep 7: Documentation Consistency

### 7a. CLAUDE.md

- References Phase 3 as COMPLETE
- References Phase 4 as next
- Lists the fix architecture accurately
- No stale Phase 2 references in Phase 3 sections
- Five-ring safeguard model documented
- Fix exit codes documented
- Key decisions listed

### 7b. README.md

- `kubevigil fix` command documented with examples
- Safety model explained
- Fix exit codes listed
- Project structure includes `internal/fix/`
- No broken internal links

### 7c. Cross-Reference

- Every check ID in the fix registry (`internal/fix/registry.go`) maps to a real checker that exists in `internal/checker/`
- Every checker backfilled with FixHint has a corresponding entry in the fix registry
- The safety classification in the registry matches the FixHint.Safety in the checker

---

## Sweep 8: Code Quality

### 8a. Linter

```bash
golangci-lint run ./internal/fix/... ./cmd/kubevigil/...
```

Zero warnings in Phase 3 code. Pre-existing warnings in Phase 1/2 code are acceptable.

### 8b. Go Vet

```bash
go vet ./...
```

### 8c. Leftover Markers

```bash
grep -rn "TODO\|FIXME\|HACK\|XXX\|TEMP\|PLACEHOLDER" internal/fix/ cmd/kubevigil/fix*.go test/e2e/scenarios/fix-* test/e2e/scripts/*fix*
```

Each marker found must be assessed:
- Is it a genuine TODO for Phase 4+? → Acceptable, but file a Tasks issue.
- Is it a forgotten placeholder from Phase 3 work? → Fix now.

### 8d. Unused Exports

```bash
# Check for exported functions in internal/fix/ that aren't used outside the package
grep -rn "^func [A-Z]" internal/fix/*.go | grep -v "_test.go"
```

For each exported function, verify it's either:
- Called from `cmd/kubevigil/fix.go`, OR
- Part of the public API intended for future use (e.g., library consumers), OR
- Used in integration/E2E tests

Unexported functions that should be exported (or vice versa) = fix now.

---

## Sweep 9: Build & Smoke Test

### 9a. Clean Build

```bash
go build ./...
```

### 9b. Binary Smoke Test

```bash
# Build binary
go build -o /tmp/kubevigil-sweep ./cmd/kubevigil

# Help works
/tmp/kubevigil-sweep fix --help

# Dry-run on safe scenario
/tmp/kubevigil-sweep fix test/e2e/scenarios/fix-safe/

# Dry-run on clean scenario (should report nothing to fix)
/tmp/kubevigil-sweep fix test/e2e/scenarios/fix-clean/

# Verify exit codes
/tmp/kubevigil-sweep fix test/e2e/scenarios/fix-safe/; echo "Exit: $?"      # Should be 0
/tmp/kubevigil-sweep fix test/e2e/scenarios/fix-clean/; echo "Exit: $?"     # Should be 4

# Clean up
rm /tmp/kubevigil-sweep
```

### 9c. E2E Manifest Mode

```bash
bash test/e2e/scripts/run-fix.sh
```

All tests should pass. If the script fails, investigate and fix.

---

## Output: Sweep Report

After completing all sweeps, produce a summary as a Tasks issue titled `phase3-final-sweep`:

```markdown
# Phase 3 Final Sweep Results

## File Inventory
- Expected: X files
- Found: Y files
- Missing: [list or "none"]
- Unexpected: [list with explanation or "none"]

## Test Health
- All tests pass: ✅/❌
- Fix package coverage: XX%
- Phase 1/2 regression: ✅/❌
- Contract test: ✅/❌ (N checkers)

## FixHint Backfill
- Expected: 20 checkers
- Verified: N/20
- Issues: [list or "none"]

## Safety Model
- System NS hard block: ✅/❌
- Risk level gating: ✅/❌
- Known workload detection: ✅/❌
- Dry-run default: ✅/❌

## YAML Round-Trip
- Comment preservation test: ✅/❌
- Key ordering test: ✅/❌
- Indentation test: ✅/❌
- Multi-doc test: ✅/❌
- Quoting test: ✅/❌

## CLI
- All flags present: ✅/❌ (missing: [list])
- All exit codes tested: ✅/❌ (missing: [list])
- Help text: ✅/❌

## Documentation
- CLAUDE.md accurate: ✅/❌
- README.md accurate: ✅/❌
- Registry↔Checker cross-ref: ✅/❌

## Code Quality
- Linter clean: ✅/❌
- Go vet clean: ✅/❌
- Leftover markers: [count] ([list of genuine TODOs filed as issues])
- Unused exports: [count]

## Build & Smoke
- Clean build: ✅/❌
- Smoke test: ✅/❌
- E2E manifest mode: ✅/❌

## Issues Filed
- [list of Tasks issues created for any findings]

## Verdict
Phase 3 is SHIPPABLE / NOT SHIPPABLE (with reasons)
```

**If the verdict is NOT SHIPPABLE**, fix all blocking issues before closing this sweep. Non-blocking issues (genuine Phase 4 TODOs, nice-to-have coverage improvements) can be filed as Tasks issues and deferred.

**If the verdict is SHIPPABLE**, close this sweep and the phase3-final-sweep Tasks issue.
