# PROMPT — Phase 3 Coverage Recovery

> **Purpose:** Restore project coverage from 87.2% back to ≥90% by closing test gaps in the Phase 3 fix engine and CLI command. This is a test-only prompt — you are writing tests, not changing implementation code. If you discover a bug while writing tests, fix it, but the goal is coverage.

---

## Pre-Flight

**Read these files before doing ANYTHING:**

- `CLAUDE.md` — Project identity, coding standards, testing rules
- `docs/internal/kubevigil-features-v3.md` **lines 561–935 only** (Section 7: Auto-Remediation Engine). Do NOT read the full file.

**Run the baseline measurement:**

```bash
go test ./... -coverprofile=coverage-before.out
go tool cover -func=coverage-before.out | tail -1
go tool cover -func=coverage-before.out | grep "internal/fix/" | awk -F'\t+' '{gsub(/%/,"",$NF); if ($NF+0 < 70) print}'
go tool cover -func=coverage-before.out | grep "cmd/kubevigil/fix" | awk -F'\t+' '{print}'
```

Record the "before" numbers. You will compare against these at the end.

---

## Coverage Targets

| Package | Current | Target | Gap |
|---------|---------|--------|-----|
| `internal/fix/` | 83.0% | ≥ 90% | ~7 points |
| `cmd/kubevigil/` (fix.go) | ~0% for runFix | ≥ 70% | major |
| **Project total** | 87.2% | ≥ 90% | ~3 points |

The project total will recover naturally once the two packages above are fixed.

---

## Priority 1: Zero-Coverage Functions (CRITICAL)

These functions have 0% coverage. They are the biggest bang-for-buck:

### 1a. `fixer.go:Verify()` — 0%

This is the `--verify` re-scan flow. Write tests that:
- Call Verify after a successful fix and assert findings are reduced
- Call Verify after a partial fix and assert remaining findings are reported
- Call Verify with no prior fix (should still work — just re-scans)

Read the function signature and understand what it takes as input. You likely need a temp directory with fixable manifests, run Plan+Apply, then call Verify.

### 1b. `gitops.go:CreateGitOpsPR()` — 0%

This calls `gh` or `glab` CLI. It's hard to test against real Git, but you CAN test:
- The function returns an error when no git CLI is found (mock `exec.LookPath`)
- The function returns an error when not in a git repo
- The branch name generation is correct (test the helper that builds the branch name)
- The PR description is correctly constructed from the fix summary

If the function is structured so the git operations are injected (interface or function params), test with mocks. If it directly calls `exec.Command`, consider refactoring the external calls behind a small interface so you can mock them. This is the ONE place where you may need to touch implementation code — adding a thin interface for testability.

### 1c. `cmd/kubevigil/fix.go:runFix()` — 0%

This is the main CLI entry point. The pattern already exists in `scan_test.go` — follow it. Test:
- Dry-run mode: pass a path with fixable manifests, no `--apply` → verify exit code 0, no files modified
- Apply mode: pass `--apply --yes` on a temp copy of fixtures → verify files were modified
- Nothing to fix: pass a clean manifest → verify exit code 4
- Bad path: pass a nonexistent path → verify exit code 2 or 3
- Risk level flag: pass `--risk-level moderate` → verify moderate fixes included in output
- System NS rejection: pass manifests with `kube-system` namespace → verify they're skipped without `--i-understand-system-namespaces`

The key pattern: create temp directories with copies of test fixtures, execute the cobra command programmatically (using `cmd.SetArgs()`), capture stdout/stderr, and assert on output + exit code + file state.

### 1d. `fix.go:printVerifyResult()` — 0%

Test by constructing a verify result struct and calling the function with a `bytes.Buffer` as writer. Assert the output contains expected counts.

### 1e. `fix.go:isTerminalWriter()` — 0%

Test with a `bytes.Buffer` (not a terminal → false) and `os.Stdout` in a test that checks the function exists and returns a bool. This is a small function — one or two test cases is sufficient.

---

## Priority 2: Functions Below 60% (HIGH)

### 2a. `fixer.go:Apply()` — 57.1%

Read the function and identify untested branches. Likely missing:
- Partial failure path: one file fails to parse, others succeed → assert PartialSuccess=true, Errors populated
- All files fail → assert no files modified, error returned
- Backup creation failure → assert fix is NOT applied (safety guarantee)
- Empty plan (no fixes to apply) → assert clean return

### 2b. `fixer.go:applyFixToDocs()` — 59.3%

Multi-document YAML patching. Missing branches likely include:
- Document with no findings → passed through unchanged
- Document parse failure in one doc of a multi-doc file → that doc skipped, others fixed
- Single-document file (no `---` separator) — simple path

### 2c. `yaml_patcher.go:navigateExisting()` — 50.0%

Path navigation for existing nodes. Test:
- Navigate to a deeply nested existing key → found
- Navigate to a key that doesn't exist → appropriate error/nil
- Navigate through a sequence (array) index → correct element
- Navigate with an invalid path segment → error

### 2d. `report.go:reportSkipReasonLabel()` — 20.0%

This is a simple switch/map function. Write a table-driven test covering every skip reason enum value.

### 2e. `gitops.go:detectGitCLI()` — 40.0%

Test all branches: `gh` found, `glab` found, neither found, both found (preference order).

---

## Priority 3: Functions Below 70% (MEDIUM)

### 3a. `yaml_patcher.go:SetNode()` and `setNodeAt()` — 66.7%

Test edge cases:
- Set value on a key that exists (overwrite)
- Set value on a key that doesn't exist (should this create or error? Test the actual behavior)
- Set value to nil/empty
- Set value with different types (string, int, bool, list, map)

### 3b. `yaml_patcher.go:navigatePathMulti()` — 65.4%

Test:
- Path with array wildcard (`containers[*]`)
- Path with specific array index (`containers[0]`)
- Path with nested arrays
- Invalid path syntax

### 3c. `report.go:WriteFixReport()` — 66.7%

Test:
- Report with mixed fix results (applied, skipped, failed)
- Report with zero fixes (clean)
- Report with partial failure
- Verify report contains restore instructions
- Verify report contains "What Could Break" warnings for non-safe fixes

### 3d. `helm_gen.go:sectionDisplayName()` — 33.3%

Table-driven test covering every section enum value.

### 3e. `kustomize_gen.go:highestRiskLevel()` — 63.6%

Table-driven test: safe-only → safe, mixed safe+moderate → moderate, mixed all → aggressive, empty → safe.

### 3f. `fix.go:skipReasonLabel()` — 62.5%

Table-driven test covering every skip reason.

### 3g. `fix.go:isInteractive()` — 60.0%

Test: CI env vars set → false, TTY stdin → true, non-TTY → false, `--yes` flag → false.

### 3h. `fix.go:printFixSummary()` — 76.3%

Test with various FixSummary shapes: all applied, all skipped, mixed, partial failure with errors.

---

## Priority 4: Strengthen Existing Tests and Close Remaining Issues (LOW)

### 4a. YAML Quoting Style Preservation (Tasks: `KubeVigil-a17x`)

Add a test to `yaml_patcher_test.go`:
- Input YAML with `key: "quoted-value"` and `other: unquoted`
- Apply a fix that modifies a different field
- Assert the quoting style of untouched fields is preserved

### 4b. `--fingerprint` Flag (Tasks: `KubeVigil-ir8l`)

The `--fingerprint` flag was specified in the prompts but deferred during implementation because the scanner doesn't generate finding fingerprints yet. Implement a minimal working version:

1. The flag already exists in `fix.go` (verify — if not, add it as `--fingerprint` accepting a string slice)
2. Add a `Fingerprint()` method to the Finding struct (or a helper in `internal/fix/`) that computes a deterministic hash from: check ID + resource kind + resource name + resource namespace + field path. Use SHA-256, truncated to 12 hex chars.
3. When `--fingerprint` is passed, filter the fix plan to only include findings whose fingerprint matches one of the provided values.
4. Add tests: compute fingerprint for a known finding, pass it to fix, verify only that finding is fixed.
5. Add a `kubevigil fix --show-fingerprints` (or include fingerprints in dry-run diff output) so users can discover fingerprint values.

If this is too large for a coverage-focused prompt, the minimum acceptable action is: verify the flag exists in the CLI, add a stub that filters by finding fingerprint with a simple hash, write one test, and close the Tasks issue. The full UX polish can happen in Phase 4.

### 4c. Multi-Document Edge Cases

Add to `yaml_patcher_test.go` or `fixer_test.go`:
- File with only `---` separators and empty documents
- File where the last document has no trailing newline
- File with three documents, middle one is empty

---

## Testing Patterns to Follow

### For `internal/fix/` tests:

```go
func TestApply_PartialFailure(t *testing.T) {
    // Create temp dir with multiple fixture files
    tmpDir := t.TempDir()
    // Copy valid fixture
    copyFixture(t, "testdata/fixable-deployment.yaml", filepath.Join(tmpDir, "good.yaml"))
    // Create malformed file
    os.WriteFile(filepath.Join(tmpDir, "bad.yaml"), []byte("not: valid: yaml: {{"), 0644)

    fixer := NewFixer(FixConfig{RiskLevel: RiskSafe, Apply: true})
    plan, _ := fixer.Plan(context.Background(), []string{tmpDir})
    summary, err := fixer.Apply(context.Background(), plan)

    assert.NoError(t, err) // Partial failure is NOT an error return
    assert.True(t, summary.PartialSuccess)
    assert.Greater(t, len(summary.Errors), 0)
    assert.Greater(t, summary.Applied, 0)
}
```

### For `cmd/kubevigil/fix.go` tests:

Follow the existing pattern in `scan_test.go`. The typical approach:

```go
func TestFixCommand_DryRun(t *testing.T) {
    tmpDir := t.TempDir()
    // Copy fixture to temp
    copyFixture(t, "../../test/e2e/scenarios/fix-safe/", tmpDir)

    // Capture original file contents
    originalBytes, _ := os.ReadFile(filepath.Join(tmpDir, "deployment.yaml"))

    // Build and execute command
    cmd := newFixCmd()
    buf := new(bytes.Buffer)
    cmd.SetOut(buf)
    cmd.SetErr(buf)
    cmd.SetArgs([]string{tmpDir})

    err := cmd.Execute()
    assert.NoError(t, err)

    // Verify files were NOT modified (dry-run)
    afterBytes, _ := os.ReadFile(filepath.Join(tmpDir, "deployment.yaml"))
    assert.Equal(t, originalBytes, afterBytes, "dry-run should not modify files")

    // Verify diff output was printed
    assert.Contains(t, buf.String(), "---")
}
```

If the command calls `os.Exit()` or uses a global root command, you may need to test via `exec.Command` running the built binary against temp fixtures. Check how `scan_test.go` handles this.

---

## Execution Order

1. Run baseline coverage measurement
2. Priority 1 (zero-coverage functions) — biggest impact
3. Run coverage again — should see significant jump
4. Priority 2 (below 60%) — second wave
5. Run coverage again — should be approaching targets
6. Priority 3 (below 70%) — polish
7. Priority 4 (edge cases) — if time permits
8. Final coverage measurement and comparison

---

## Completion Criteria

Run the final measurement:

```bash
go test ./... -coverprofile=coverage-after.out
go tool cover -func=coverage-after.out | tail -1
echo "=== Fix package ==="
go test ./internal/fix/... -cover
echo "=== Cmd package ==="
go test ./cmd/kubevigil/... -cover
```

**Must achieve ALL of:**
- [ ] `internal/fix/` ≥ 90% (currently 83%)
- [ ] `cmd/kubevigil/` ≥ 55% (currently 43.9% — achieving 70% for fix.go alone will lift this)
- [ ] Project total ≥ 90% (currently 87.2%)
- [ ] Zero functions at 0% coverage in Phase 3 code
- [ ] ALL existing tests still pass (zero regressions)
- [ ] Tasks clean: `KubeVigil-13a8`, `KubeVigil-a17x`, `KubeVigil-ir8l` all closed

**Report format:**

```
Coverage Recovery Results:
  Before: 87.2% total | 83.0% fix | 43.9% cmd
  After:  XX.X% total | XX.X% fix | XX.X% cmd

  Functions recovered from 0%:
    - Verify(): 0% → XX%
    - CreateGitOpsPR(): 0% → XX%
    - runFix(): 0% → XX%
    - printVerifyResult(): 0% → XX%
    - isTerminalWriter(): 0% → XX%

  Tests added: N new test functions across M files
  Regressions: none / [list]
```

Close Tasks issue `KubeVigil-13a8` when coverage targets are met. Close `KubeVigil-a17x` when quoting style test is added. Close `KubeVigil-ir8l` when the `--fingerprint` flag is functional with at least one test. **All three Tasks issues must be closed for this prompt to be complete.**

---

## Rules

- **TDD still applies** — but here you're writing tests for existing code, so the cycle is: write test → run it → verify it passes (it should, since the code exists). If a test FAILS, you found a bug — fix the implementation.
- **Do NOT refactor implementation code for coverage.** The only exception is adding a thin interface to `gitops.go` for mocking external CLI calls.
- **Do NOT weaken existing tests** to make coverage numbers look better.
- **Do NOT add empty/trivial tests** that exercise code without meaningful assertions.
- **Every test must assert something meaningful** — a test that calls a function and ignores the result doesn't count.
