# Phase 3c — CLI Command: `kubevigil fix` with Full User Experience

## Context

You are continuing Phase 3 of KubeVigil. **Prompts 3a and 3b are complete.** The following now exist:

- `internal/fix/types.go` — All fix types (FixSafety, FixOp, FixHint, FixResult, FixSummary, FixConfig, etc.)
- `internal/fix/registry.go` — Fix strategy registry for all auto-fixable checks
- `internal/fix/yaml_patcher.go` — YAML round-trip patcher with comment/format preservation
- `internal/fix/safety.go` — System namespace detection, risk level filtering, known workload detection
- `internal/fix/fixer.go` — Core fixer orchestrator (Plan → Apply → Verify pipeline)
- `internal/fix/backup.go` — Structured backup creation with restore instructions
- `internal/fix/diff.go` — Unified diff generation with ANSI color support
- All tests passing, including integration test (scan → fix → re-scan → zero findings)

**Read these files before doing ANYTHING:**
- `CLAUDE.md` — Project identity, coding standards, workflow rules
- `docs/internal/kubevigil-features-v3.md` **lines 561–935 only** (Section 7, especially 7.1 Dry-Run Default, 7.3 Layered Safeguards, 7.4 Impact Summary, 7.9 CLI Reference, 7.10 Ignorant vs Knowledgeable Gate). Do NOT read the full file.
- `cmd/kubevigil/scan.go` — Existing scan command (follow the same Cobra patterns)
- `cmd/kubevigil/root.go` — Root command setup
- `internal/fix/fixer.go` — Core fixer from 3b

This prompt (3c) builds the **CLI command** that exposes the fix engine to users, with all safeguards, user experience, and interactive features.

## Objectives

### 1. Create `cmd/kubevigil/fix.go`

The `kubevigil fix` Cobra command with all flags:

```go
// Flags
var fixCmd = &cobra.Command{
    Use:   "fix [path]",
    Short: "Auto-remediate security findings in Kubernetes manifests",
    Long:  `Scans manifests, identifies fixable security issues, and patches them.
By default, shows what would change (dry-run). Use --apply to modify files.`,
    Args:  cobra.ExactArgs(1), // path is required
    RunE:  runFix,
}

// Flag groups:
// Execution control
--apply                          // Actually modify files (default: dry-run)
--yes                            // Skip interactive confirmation
--verify                         // Re-scan after applying fixes

// Risk control
--risk-level string              // "safe" (default), "moderate", "aggressive"
--i-understand-system-namespaces // Allow fixing system namespace resources

// Filtering (reuse scan's filtering patterns)
--checks string                  // Comma-separated check IDs
--severity string                // Comma-separated severity levels
--namespace string               // Comma-separated namespaces to include
--exclude-namespace string       // Comma-separated namespaces to exclude
--exclude-infra                  // Exclude infrastructure namespaces

// Output control
--output string                  // "diff" (default), "kubectl", "helm-values"
--kustomize string               // Path for Kustomize overlay output
--report string                  // Custom path for fix report
--backup-dir string              // Custom backup directory

// Git integration
--git-pr                         // Create branch and PR (requires gh/glab)
```

### 2. Interactive Confirmation System

When `--apply` is set and the fix plan exceeds the bulk threshold (default 10 files):

```
⚠️  This will modify 47 files across 12 namespaces.

  Safe fixes:           31 (will be applied)
  Skipped (system ns):   8 (protected)
  Skipped (risk > safe): 8 (use --risk-level to include)
  
  Namespaces affected: production, staging, dev, qa, ...
  Backup directory:    ./manifests.bak-20260217T143022/
  
  Review the dry-run output first?  [Y/n]    ← defaults to YES
  Apply 31 safe fixes?              [y/N]    ← defaults to NO
```

Implementation:
- Detect TTY via `os.Stdin` and `isatty` (golang.org/x/term or simple stat check)
- Default answers: "Review?" → Yes, "Apply?" → No (safe defaults)
- `--yes` bypasses all prompts
- Non-TTY without `--yes` → error with guidance message

### 3. CI Mode Detection

When running in CI (detected by `CI=true` env var, `GITHUB_ACTIONS=true`, `GITLAB_CI=true`, `JENKINS_URL` set, or non-TTY stdin):

- `--apply` without `--yes` fails immediately:
  ```
  Error: --apply in non-interactive mode requires --yes flag.
  Hint: Run 'kubevigil fix <path>' first to review changes, then add --yes for CI.
  ```
- With `--apply --yes`, proceeds without prompts but STILL prints the full fix summary to stdout (visible in CI logs)

### 4. Fix Summary Output

After every fix operation (dry-run or applied), print a clear summary:

```
KubeVigil Fix Summary
─────────────────────
Files scanned:       156
Files to modify:      23
Findings total:       65

By risk classification:
  ✅ Safe:              31  [applied]
  ⚠️  Likely safe:       12  [skipped — use --risk-level moderate]
  🔶 Potentially breaking: 4 [skipped — use --risk-level aggressive]
  📋 Manual only:         0  [guidance below]

Skipped:
  🛡️  System namespaces:  14  [kube-system(8), rook-ceph(4), calico-system(2)]
  🏷️  Exempted:            3  [annotation-based]
  ✔️  Already fixed:        1

Backup: ./manifests.bak-20260217T143022/
Report: ./manifests.bak-20260217T143022/FIX-REPORT.md

To restore: cp -r ./manifests.bak-20260217T143022/* ./manifests/
```

For dry-run (no `--apply`), append:
```
This was a dry-run. No files were modified.
To apply these fixes: kubevigil fix ./manifests/ --apply
```

### 5. Diff Output (Default Mode)

When not using `--apply` (dry-run) or with `--output diff`:

```diff
--- production/deployment-web.yaml (original)
+++ production/deployment-web.yaml (fixed)
@@ -15,6 +15,7 @@
       containers:
       - name: web
         image: nginx:1.25
+        # KubeVigil: privileged set to false (check: privileged, risk: safe)
         securityContext:
-          privileged: true
+          privileged: false
+          allowPrivilegeEscalation: false
+          readOnlyRootFilesystem: true
```

Color the diff when output is a TTY. Plain text when piped.

**Inline "What Could Break" Warnings:** For fixes classified as "likely_safe" or "potentially_breaking", the diff output MUST include an impact warning directly below the relevant change. This is critical for ignorant users who will only see the diff output and never read the fix report:

```diff
--- production/deployment-web.yaml (original)
+++ production/deployment-web.yaml (fixed)
@@ -18,3 +18,4 @@
         securityContext:
+          readOnlyRootFilesystem: true
# ⚠️  IMPACT (likely_safe): Applications writing to the container filesystem
#     (temp files, caches, logs) will fail. Add emptyDir volumes for writable paths.
```

This ensures the user sees the risk at the point of change, not buried in a report. For "safe" fixes, no warning is needed.

### 6. Kubectl Output Mode

With `--output kubectl`:

```bash
# KubeVigil kubectl patch commands
# Generated: 2026-02-17T14:30:22Z
# Risk level: safe

# --- Namespace: production (12 patches) ---

# Fix: privileged=true → false (check: privileged, severity: Critical)
kubectl patch deployment web-frontend -n production --type=strategic -p '{"spec":{"template":{"spec":{"containers":[{"name":"web","securityContext":{"privileged":false}}]}}}}'

# Fix: missing allowPrivilegeEscalation=false (check: privilege-escalation, severity: High)
kubectl patch deployment web-frontend -n production --type=strategic -p '{"spec":{"template":{"spec":{"containers":[{"name":"web","securityContext":{"allowPrivilegeEscalation":false}}]}}}}'

# --- Namespace: staging (8 patches) ---
# ...
```

**Namespace filtering applies to kubectl output identically to fix operations.** The `--namespace`, `--exclude-namespace`, and `--exclude-infra` flags filter which findings produce kubectl patches. The namespace used in each `kubectl patch` command comes from the finding's `Namespace` field (populated during scan from `metadata.namespace` in the manifest). If a manifest doesn't specify a namespace, the patch uses `-n default` and a comment warns the operator to verify the target namespace.

### 7. Exit Codes

Extend the existing exit code system:

| Code | Meaning |
|------|---------|
| `0` | Fix successful (all planned fixes applied, or dry-run shows changes) |
| `1` | Fix applied but --verify found remaining findings |
| `2` | Fix error (file I/O, YAML parse error, backup failed — total failure) |
| `3` | Configuration error (invalid flags, conflicting options) |
| `4` | No fixable findings found (nothing to do — informational, not error) |
| `5` | Partial success — some fixes applied but N files failed (see fix report for details) |

### 8. Wiring into Root Command

Register the fix command in `cmd/kubevigil/root.go` following the existing pattern for scan, list, version.

### 9. Config File Integration for System Namespaces

The existing config system (`internal/config/`) supports `.kubevigil.yaml`. Extend it to support fix-specific configuration:

```yaml
# .kubevigil.yaml
fix:
  # Additional system namespaces (extends the built-in default list, does NOT replace it)
  additionalSystemNamespaces:
    - "custom-infra"
    - "my-operator-system"
    - "vault"
  # Override bulk confirmation threshold (default: 10 files)
  bulkThreshold: 20
  # Default backup directory (default: <source>.bak-<timestamp>/)
  backupDir: "/tmp/kubevigil-backups/"
```

Rules:
- `additionalSystemNamespaces` is ADDITIVE — it extends `DefaultSystemNamespaces` from `safety.go`, never replaces it
- A user cannot use config to remove a built-in system namespace from protection
- CLI flags always override config file values
- The existing config loading pattern in `internal/config/` should be followed

## Testing Requirements — TDD is Mandatory

### Required Tests

1. **`cmd/kubevigil/fix_test.go`** — CLI-level tests:
   - Dry-run default: running without --apply produces diff output, no file modifications
   - `--apply` flag: files are modified
   - `--apply` without `--yes` in non-TTY mode: exits with error
   - Risk level flags: `--risk-level safe`, `moderate`, `aggressive`
   - `--i-understand-system-namespaces` flag
   - `--checks` filtering
   - `--severity` filtering
   - `--namespace` filtering
   - `--exclude-namespace` filtering
   - `--output kubectl` produces valid kubectl commands
   - `--output helm-values` produces Helm values (deferred to 3d)
   - `--kustomize` flag (deferred to 3d)
   - `--verify` flag triggers re-scan
   - `--backup-dir` custom backup path
   - Exit codes: 0, 1, 2, 3, 4, 5 per specification
   - Exit code 5: partial success when some files fail during patching
   - Help text includes all flags
   - Path argument required (no args → error)
   - Dry-run diff output includes inline "What Could Break" warnings for likely_safe/potentially_breaking fixes
   - Config file `.kubevigil.yaml` `fix.additionalSystemNamespaces` extends default system NS list
   - Config file `fix.bulkThreshold` overrides default confirmation threshold
   - CLI flags override config file values

2. **CI mode tests:**
   - `CI=true` env var detection
   - Non-TTY detection
   - Error message when --apply without --yes in CI

3. **Integration with existing CLI tests** — The fix command doesn't break existing scan, list, version commands.

### Test Approach

Use the same testing patterns as `cmd/kubevigil/cli_test.go` and `cmd/kubevigil/scan_filter_test.go`. Create temp directories with fixture YAML, run the fix command, verify output and file state.

## Tasks Integration

File issues:
- `phase3-fix-command` — Cobra command with all flags
- `phase3-interactive-confirmation` — TTY detection, prompts, --yes flag
- `phase3-ci-mode` — CI environment detection and behavior
- `phase3-fix-summary-output` — Summary display formatting
- `phase3-exit-codes` — Fix-specific exit codes
- `phase3-diff-output-mode` — Default diff display
- `phase3-kubectl-output-mode` — kubectl patch generation display

Dependencies: All depend on phase3-fixer-orchestrator (from 3b).

## Quality Gates

1. `go test ./...` passes (ALL tests)
2. `go vet ./...` clean
3. `golangci-lint run` clean
4. Manual verification: build binary, run `kubevigil fix --help`, verify all flags present
5. Dry-run produces readable diff on sample fixture
6. `--apply` with fixture modifies files correctly
7. CI mode error works as specified
8. Tasks issues filed and updated
9. `git push` to remote

## Files Created/Modified

### New Files
- `cmd/kubevigil/fix.go` + test coverage in `cmd/kubevigil/fix_test.go`

### Modified Files
- `cmd/kubevigil/root.go` — Register fix command
