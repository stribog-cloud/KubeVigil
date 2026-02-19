# PROMPT — Test Coverage Audit & Remediation

> **Role:** You are a test coverage auditor. Your job is to systematically identify every meaningful test gap across the entire KubeVigil codebase, file each gap as a Tasks issue, then fix them using sub-agents and agent teams. When you are done, Tasks should be clean (all issues closed) and every function that warrants a test should have one.

---

## Pre-Flight

**Read these files before doing ANYTHING:**

- `CLAUDE.md` — Project standards, testing rules, coding patterns
- `AGENTS.md` — Tasks workflow, session completion rules

---

## Phase A: Discovery (Audit)

### A1. Measure Baseline

```bash
go test ./... -coverprofile=coverage-audit-before.out
go tool cover -func=coverage-audit-before.out | tail -1
```

Record the starting number.

### A2. Generate the Complete Gap Inventory

Run the following analysis and classify every uncovered or under-covered function:

```bash
# All functions below 85% coverage
go tool cover -func=coverage-audit-before.out | awk -F'\t+' '{gsub(/%/,"",$NF); if ($NF+0 < 85 && $NF+0 > 0) print}'

# All functions at exactly 0%
go tool cover -func=coverage-audit-before.out | awk -F'\t+' '{gsub(/%/,"",$NF); if ($NF+0 == 0) print}'

# Per-package summary
go test ./... -cover 2>&1 | grep "^ok"
```

### A3. Classify Every Gap

For EACH function identified, read the source code and assign it to exactly one category:

**Category 1 — TESTABLE: Real logic that needs tests.**
Functions with branching, computation, parsing, state mutation, or non-trivial behavior. These MUST get tests.

Examples: `hasNetworkPolicyBlockingIMDS` (25%), `detectProvider` (68%), `extractPodSpec` (55%), `matchesUntrustedValues` (0%), `parseYAMLBytes` (75%), `applyFixToDocs` (81%), helper functions with switch/if logic.

**Category 2 — TRIVIAL GETTERS: One-liner interface methods returning constants.**
Methods like `SupportedModes()`, `RequiredResources()`, `Description()`, `Categories()` that just `return []string{...}`. These are already exercised by the contract test (`test/integration/contract_test.go`), which calls every registered checker's interface methods. They show as 0% because Go's coverage tool attributes coverage to the package being tested, not the package being called.

Action: Do NOT write individual unit tests for these. Instead, verify the contract test covers them by running:
```bash
go test ./test/integration/... -v -run TestContract -coverprofile=contract-cover.out
go tool cover -func=contract-cover.out | grep "SupportedModes\|RequiredResources\|Description\|Categories" | head -20
```

If the contract test does NOT exercise them, add a single comprehensive test that iterates all checkers and calls every interface method. File ONE Tasks issue for this, not one per function.

**Category 3 — CLI ENTRY POINTS: Top-level command runners.**
Functions like `main()`, `runScan()`, `runListChecks()`, `execute()`, `Error()`. These are the outermost shells that wire everything together.

Action: For `runScan` and `runListChecks`, write integration-style tests that execute the Cobra command programmatically (using `cmd.SetArgs()` + `cmd.Execute()`) against fixture files. Follow the pattern in existing `fix_test.go` or `scan_test.go`. For `main()` and `Error()`, these are trivially thin — skip them.

**Category 4 — LIVE-CLUSTER ONLY: Code requiring a real Kubernetes cluster.**
Functions like `ScanLive()`, `NewClient()`, `ClusterVersion()`. These cannot be meaningfully unit-tested without a cluster.

Action: Do NOT write mock-heavy unit tests for these. They are covered by the E2E `run-fix-live.sh` and similar scripts. Skip with a one-line comment: `// Tested via E2E (test/e2e/scripts/)`. File no Tasks issues for these.

**Category 5 — TEST HELPERS: Functions in `test/helpers/` that exist to support other tests.**
`AssertNoFindings`, `AssertFindingCount`, `WithVolume`, etc. These show as 0% because they're called FROM test files, and Go's coverage tool doesn't cross-attribute.

Action: Verify these are actually used by grepping for their names across test files. If a helper is unused → delete it. If it's used → it's implicitly tested. Do NOT write "tests for tests." File no Tasks issues.

**Category 6 — SKIP: Functions where testing adds no value.**
- `main()` — one line calling `execute()`
- Truly dead code — delete it instead of testing it
- Auto-generated code

Action: Delete dead code. Skip the rest. File no Tasks issues.

### A4. File Tasks Issues

After classification, file ONE Tasks issue per logical group of gaps. Do NOT file one issue per function — group by package and category.

Naming pattern: `test-audit-<package>-<category>`

Examples:
- `test-audit-checker-cloud-logic` — covers hasNetworkPolicyBlockingIMDS, detectProvider, etc.
- `test-audit-checker-scheduling-helpers` — covers extractPodSpec, gvrForKind, workloadHasRequests
- `test-audit-cmd-integration` — covers runScan, runListChecks via Cobra tests
- `test-audit-fix-yaml-patcher-edges` — covers setNodeAt, navigateExisting, RemoveNode edge cases
- `test-audit-fix-generators` — covers helm_gen, kustomize_gen, report low-coverage branches
- `test-audit-contract-coverage` — if trivial getters aren't covered by contract test

Each issue should contain:
- List of specific functions and their current coverage %
- What kind of tests to write (table-driven, integration, edge-case, error-path)
- Estimated effort: S (1-3 tests), M (4-8 tests), L (9+ tests)
- Priority: P1 (logic at 0%), P2 (logic below 60%), P3 (logic 60-85%)

**Do NOT start fixing until ALL issues are filed.** The audit must be complete before remediation begins.

---

## Phase B: Remediation (Fix)

### B1. Execution Strategy

Use **sub-agents** for independent package work — each package's tests can be written in isolation. Use **agent teams** when tests in one package depend on understanding another (e.g., writing CLI integration tests that exercise checker + engine + fix together).

Recommended parallelization (sub-agents can work simultaneously):

| Sub-Agent | Scope | Issues |
|-----------|-------|--------|
| Agent 1 | `internal/checker/cloud/` + `internal/checker/cluster/` | test-audit-checker-cloud-logic, test-audit-checker-cluster-logic |
| Agent 2 | `internal/checker/scheduling/` + `internal/checker/network/` + `internal/checker/secrets/` + `internal/checker/supply_chain/` | test-audit-checker-scheduling-helpers, etc. |
| Agent 3 | `internal/fix/` (yaml_patcher, generators, report edges) | test-audit-fix-yaml-patcher-edges, test-audit-fix-generators |
| Agent 4 | `cmd/kubevigil/` (CLI integration tests) + `internal/engine/` | test-audit-cmd-integration, test-audit-engine-logic |
| Agent 5 | Cross-cutting: contract test, test helper cleanup, dead code removal | test-audit-contract-coverage, test-audit-helpers-cleanup |

Adjust this plan based on what you actually find in Phase A. If a package has only 1-2 gaps, merge it with another agent's scope.

### B2. Test Writing Rules

**Every test must follow existing project patterns:**

1. **Table-driven tests** — use `testCases := []struct{ name string; ... }` with `t.Run(tc.name, ...)`. This is the dominant pattern in the codebase. Follow it.

2. **Fixture-based tests** — for checker tests, use `test/fixtures/<check-id>/` with passing and failing YAML. Use `helpers.LoadFixtureDir()` to load them.

3. **Meaningful assertions** — every test must assert something specific. A test that calls a function and ignores the result is worthless. Assert: return values, error conditions, state changes, output content.

4. **Error path coverage** — for every function with error returns, test at least one error case. Pass nil inputs, malformed data, missing files, invalid enum values.

5. **Boundary conditions** — empty slices, nil maps, zero-length strings, single-element collections, maximum values.

6. **No mocks unless necessary** — prefer real fixtures and temp directories over mocking. The only acceptable mock targets are external CLI calls (`gh`, `glab`, `kubectl`) and Kubernetes API clients.

7. **Test file location** — tests go in `*_test.go` alongside the source file they test. No separate test directories.

8. **Do NOT refactor implementation code** unless you find a bug. If a test reveals a bug, fix the bug and document it in the Tasks issue.

### B3. Quality Gates Per Issue

Before closing each Tasks issue, verify:

```bash
# All tests pass
go test ./<package>/... -count=1

# Coverage improved
go test ./<package>/... -cover

# No regressions in other packages
go test ./... -count=1
```

### B4. What NOT to Test

Do not write tests for:
- `main()` functions
- One-liner getters already covered by contract tests (verify first)
- `test/helpers/` assertion functions (they ARE tests)
- Code that only runs against a live Kubernetes cluster (ScanLive, NewClient)
- Auto-generated or trivially simple code (single return statement, no branching)

If you're unsure whether a function warrants a test, apply this rule: **"Does this function contain an `if`, `switch`, `for`, or error return?"** If yes → test it. If no → probably skip it.

---

## Phase C: Verification

### C1. Final Coverage Measurement

```bash
go test ./... -coverprofile=coverage-audit-after.out
go tool cover -func=coverage-audit-after.out | tail -1

# Compare
echo "Before: $(go tool cover -func=coverage-audit-before.out | tail -1)"
echo "After:  $(go tool cover -func=coverage-audit-after.out | tail -1)"

# Per-package comparison
echo "=== Packages that improved ==="
# (compare before/after per-package numbers)
```

### C2. Remaining 0% Functions

```bash
go tool cover -func=coverage-audit-after.out | awk -F'\t+' '{gsub(/%/,"",$NF); if ($NF+0 == 0) print}'
```

Every function still at 0% must be in one of these categories:
- `main()` — acceptable
- Trivial getter covered by contract test — acceptable (note: still shows 0% in per-package coverage, this is a Go tooling limitation)
- Live-cluster-only code — acceptable
- Test helper — acceptable

If ANY function at 0% does not fit these categories, it's a missed gap. Fix it.

### C3. Remaining Functions Below 85%

```bash
go tool cover -func=coverage-audit-after.out | awk -F'\t+' '{gsub(/%/,"",$NF); if ($NF+0 < 85 && $NF+0 > 0) print}'
```

For each remaining function below 85%, document WHY it's acceptable:
- Untestable error paths (OS-level failures, disk full, permission denied)
- External dependency paths (git CLI not found, network errors)
- Diminishing returns (already at 80%+ and remaining branches are trivial)

### C4. Tasks Cleanup

```bash
bd ready   # Should return nothing
bd list    # All issues should be closed
```

**Every Tasks issue filed in Phase A must be closed.** If an issue was filed but the gap turned out to not warrant tests (reclassified during remediation), close it with a reason explaining why.

### C5. Regression Check

```bash
go test ./... -race -count=1
go vet ./...
go build ./...
```

ALL must pass. Zero regressions.

---

## Completion Criteria

- [ ] Phase A complete: every function below 85% classified, Tasks issues filed
- [ ] Phase B complete: all warranted tests written, all Tasks issues closed
- [ ] Phase C complete: final measurement taken, 0% functions justified, regressions clean
- [ ] Coverage improved (target: meaningful improvement over starting point — not a fixed number, but every testable gap should be closed)
- [ ] Tasks is CLEAN: zero open issues
- [ ] `go test ./... -race -count=1` passes
- [ ] `go vet ./...` clean
- [ ] `go build ./...` clean
- [ ] Git committed and pushed per AGENTS.md protocol

---

## Output: Audit Report

Produce this as your final output:

```
Test Coverage Audit Report
==========================

Baseline: XX.X%
Final:    XX.X%
Delta:    +X.X%

Package Coverage Changes:
  <package>: XX% → XX%
  ...

Issues Filed and Resolved:
  <issue-id>: <title> — <N tests added> — CLOSED
  ...

Functions Still Below 85% (justified):
  <function>: XX% — <reason>
  ...

Functions Still at 0% (justified):
  <function>: <category> — <reason>
  ...

Tests Added: N new test functions across M files
Tests Modified: N existing test functions enhanced
Dead Code Removed: N functions deleted
Regressions: none
```

---

## Rules

- **Audit first, fix second.** Complete ALL of Phase A before starting Phase B.
- **File issues before fixing.** Every gap gets a Tasks issue BEFORE you write the test.
- **Close issues after fixing.** Verify coverage improved before closing.
- **Do not chase vanity coverage.** Testing a one-liner getter to move 0% → 100% is worthless if the contract test already exercises it. Focus on functions with real logic.
- **Do not weaken existing tests.** Never remove assertions or reduce test strictness.
- **Do not refactor production code** unless you find a bug.
- **Use sub-agents for parallel work.** Independent packages should be handled concurrently.
- **Land the plane.** Follow AGENTS.md — push everything when done.
