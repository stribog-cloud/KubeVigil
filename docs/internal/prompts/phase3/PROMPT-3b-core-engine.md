# Phase 3b — Core Fix Engine: Fixer Orchestrator, YAML Patcher, Backup System

## Context

You are continuing Phase 3 of KubeVigil. **Prompt 3a is complete.** The following now exist:

- `internal/fix/types.go` — FixSafety, FixOp, FixHint, FixResult, FixSummary types
- `internal/fix/registry.go` — Fix strategy registry mapping check IDs to fix strategies
- `internal/fix/yaml_patcher.go` — YAML round-trip parser with node-level manipulation (FindNode, SetNode, AddNode, RemoveNode)
- `internal/fix/safety.go` — System namespace detection, risk level filtering
- `internal/fix/known_workloads.go` — Known system workload detection by image patterns
- `internal/checker/checker.go` — Finding struct extended with CurrentValue, DesiredValue, FixHint
- All tests passing

**Read these files before doing ANYTHING:**
- `CLAUDE.md` — Project identity, coding standards, workflow rules
- `docs/internal/kubevigil-features-v3.md` **lines 561–935 only** (Section 7: Auto-Remediation Engine). Do NOT read the full file.
- `internal/fix/types.go` — Fix types from 3a
- `internal/fix/yaml_patcher.go` — YAML round-trip foundation from 3a
- `internal/fix/registry.go` — Fix strategy registry from 3a
- `internal/fix/safety.go` — Safety classification from 3a

This prompt (3b) builds the **core fix engine**: the fixer orchestrator that ties scanning, fix classification, YAML patching, and backup together.

## Objectives

### 1. Fixer Orchestrator (`internal/fix/fixer.go`)

The fixer is the central engine. Its workflow:

1. **Scan** — Run manifest scan on target path(s) to produce findings
2. **Filter** — Apply namespace, severity, check, and fingerprint filters
3. **Classify** — Match each finding against the fix registry. Classify by safety level.
4. **Gate** — Filter out fixes above the configured risk level. Hard-block system namespaces (unless overridden).
5. **Detect** — Identify known system workloads and skip/warn.
6. **Plan** — Group fixes by file. Detect fix conflicts (multiple fixes targeting same YAML node).
7. **Backup** — Create structured backup of files that will be modified.
8. **Patch** — Apply YAML patches using the round-trip patcher.
9. **Verify** (optional) — Re-scan patched files to confirm zero findings.
10. **Report** — Generate fix summary and detailed fix report.

```go
type Fixer struct {
    registry    *FixRegistry
    scanner     // interface to reuse existing scan engine
    config      FixConfig
}

type FixConfig struct {
    RiskLevel                RiskLevel
    Apply                    bool     // false = dry-run only
    Verify                   bool     // re-scan after fix
    Yes                      bool     // skip interactive confirmation
    BackupDir                string   // custom backup directory
    IncludeSystemNamespaces  bool     // --i-understand-system-namespaces
    Checks                   []string // filter by check ID
    Severities               []string // filter by severity
    Namespaces               []string // filter by namespace
    ExcludeNamespaces        []string // exclude namespaces
    ExcludeInfra             bool     // exclude infra namespaces
    BulkThreshold            int      // files threshold for confirmation (default: 10)
    SystemNamespaces         []string // override default system namespace list
}

type FixPlan struct {
    Files     map[string]*FilePlan  // path → fixes for that file
    Summary   FixSummary
}

type FilePlan struct {
    Path      string
    Fixes     []PlannedFix
    Conflicts []FixConflict  // when multiple fixes target same node
}

type PlannedFix struct {
    Finding   checker.Finding
    Strategy  FixStrategy
    Applied   bool
    SkipReason string
}

type FixConflict struct {
    FieldPath string
    Fixes     []PlannedFix
    Resolution string // which fix won and why
}

// Fix is the main entry point
func (f *Fixer) Fix(ctx context.Context, paths []string) (*FixPlan, error)

// Plan creates a fix plan without applying anything
func (f *Fixer) Plan(ctx context.Context, paths []string) (*FixPlan, error)

// Apply executes a fix plan
func (f *Fixer) Apply(ctx context.Context, plan *FixPlan) (*FixSummary, error)
```

### 1a. Partial Failure Handling (CRITICAL)

The fixer MUST be resilient to per-file failures. When patching file 150 of 200 fails (malformed YAML, permission denied, unexpected structure), the fixer continues with the remaining files and collects errors for reporting. **No all-or-nothing behavior.**

Add error tracking to `FixSummary`:

```go
type FixError struct {
    FilePath string `json:"file_path"`
    Error    string `json:"error"`
    Phase    string `json:"phase"` // "parse", "patch", "write", "backup"
}

// Add to FixSummary:
type FixSummary struct {
    // ... existing fields ...
    Errors        []FixError `json:"errors,omitempty"`
    PartialSuccess bool      `json:"partial_success"` // true when some files succeeded but others failed
}
```

Implementation rules:
- Each file is patched independently in a try/recover pattern
- A failed file does NOT roll back already-patched files
- A failed file does NOT stop processing of remaining files
- Failed files are reported in the fix summary with file path, error message, and which phase failed
- The backup for a failed file (if backup was already created) is kept — don't clean it up
- Exit code 5 (partial success) when some files patched but others failed (see 3c)
```

### 2. Backup System (`internal/fix/backup.go`)

Create structured backups before modifying files:

```go
// CreateBackup creates a backup directory and copies original files
func CreateBackup(files []string, backupDir string) (string, error)

// GenerateRestoreInstructions creates RESTORE.md in the backup directory
func GenerateRestoreInstructions(backupDir string, files []string) error

// DefaultBackupDir generates a timestamped backup directory name
func DefaultBackupDir(sourcePath string) string
// Returns: <sourcePath>.bak-<YYYYMMDDTHHMMSS>/
```

The backup directory mirrors the source structure:
```
./manifests.bak-20260217T143022/
├── production/
│   ├── deployment-web.yaml
│   └── deployment-api.yaml
├── staging/
│   └── deployment-web.yaml
└── RESTORE.md
```

### 3. Diff Generation (`internal/fix/diff.go`)

Generate unified diffs for dry-run output:

```go
// GenerateDiff produces a unified diff between original and patched content
func GenerateDiff(originalPath string, original, patched []byte) string

// ColorDiff adds ANSI color codes to a unified diff
func ColorDiff(diff string) string
// Red for removed lines, green for added lines, cyan for headers
```

Use Go standard library or a minimal diff implementation. Do NOT add a heavy dependency for this — unified diff is a simple algorithm.

### 4. Fix Conflict Detection

When multiple findings target overlapping YAML paths in the same file:

- Fixes to different fields within the same parent: **merge** (both applied).
- Fixes to the same field with same value: **deduplicate** (apply once).
- Fixes to the same field with different values: **higher severity wins**, report conflict.

Example: `privileged` check wants `securityContext.privileged: false` and `privilege-escalation` check wants `securityContext.allowPrivilegeEscalation: false` — these target different fields under the same parent. Both apply.

### 5. Multi-Document YAML Handling

When a file contains multiple YAML documents (`---` separator):

- Parse each document separately
- Fix only documents that have findings
- Preserve untouched documents byte-for-byte
- Reassemble with original `---` separators
- Preserve leading/trailing comments on document separators

### 6. Integration with Existing Scan Engine

The fixer reuses the existing `engine.ScanManifest()` function to produce findings. It does NOT reimplement scanning. The integration:

```go
// The fixer calls the scan engine internally
findings, err := engine.ScanManifest(ctx, paths, config)

// Then processes findings through the fix pipeline
for _, finding := range findings {
    strategy := f.registry.Get(finding.Checker)
    if strategy == nil {
        // No fix available — report as manual-only
        continue
    }
    // ... classify, filter, plan ...
}
```

## Testing Requirements — TDD is Mandatory

### Required Tests

1. **`internal/fix/fixer_test.go`** — THE core test file:
   - Full pipeline: fixture → scan → plan → apply → verify files changed correctly
   - Dry-run mode: plan generates results but files untouched
   - Risk level filtering: safe-only, moderate, aggressive
   - System namespace hard block
   - Known workload skip
   - Selective fix by check ID, severity, namespace
   - Fix conflict detection and resolution
   - Multi-document YAML: only affected documents changed
   - Empty plan (no fixable findings) — graceful no-op
   - Already-fixed files — no changes, skip reported

   **Partial failure tests (CRITICAL):**
   - File with malformed YAML: patching fails for that file, continues with remaining files
   - File with permission denied (read-only): fails for that file, continues with others
   - Mixed success: 3 files fixable, 1 fails → 3 patched, 1 error reported, PartialSuccess=true
   - All files fail: Errors populated, Applied=0, summary reflects total failure
   - Error details include file path, error message, and phase (parse/patch/write/backup)

2. **`internal/fix/backup_test.go`**:
   - Backup directory created with correct structure
   - Files copied correctly
   - RESTORE.md generated with correct commands
   - Backup with custom directory path
   - Backup with nested source directories
   - Backup when file is read-only
   - Cleanup: use `t.TempDir()` for all backup tests

3. **`internal/fix/diff_test.go`**:
   - Simple field change produces correct unified diff
   - Added field shows in diff
   - Removed field shows in diff
   - Multiple changes in one file
   - No changes produces empty diff
   - File path headers correct in diff output

4. **Integration test** — In `test/integration/`:
   - Scan → Fix → Re-scan → Zero findings (the golden workflow)
   - Use real fixture files from `test/fixtures/fix/`
   - Verify YAML round-trip: comments preserved, formatting preserved

### Test Fixtures

Extend `test/fixtures/fix/` (from 3a) with:
- `multi-finding.yaml` — Deployment with multiple security issues (privileged, no caps drop, no readOnlyRootFilesystem, etc.)
- `system-namespace.yaml` — Resources in kube-system namespace
- `known-workload-calico.yaml` — Calico DaemonSet with expected elevated privileges
- `multi-doc-mixed.yaml` — Multi-document file where only some documents need fixes
- `conflict-same-field.yaml` — Resource where two checks want to modify overlapping fields
- `already-secure.yaml` — Fully hardened deployment (zero findings expected)

## Tasks Integration

File issues:
- `phase3-fixer-orchestrator` — depends on: phase3-fix-registry, phase3-yaml-patcher, phase3-safety-classification
- `phase3-backup-system` — standalone
- `phase3-diff-generation` — standalone
- `phase3-fix-conflict-resolution` — depends on: phase3-fixer-orchestrator
- `phase3-multi-document-handling` — depends on: phase3-yaml-patcher
- `phase3-scan-fix-integration` — depends on: phase3-fixer-orchestrator (integration test)

## Quality Gates

1. `go test ./...` passes (ALL tests, including Phase 1, 2, and 3a)
2. `go vet ./...` clean
3. `golangci-lint run` clean
4. Integration test: scan → fix → re-scan → zero findings passes
5. YAML round-trip verified in integration test
6. Test coverage for new code ≥ 85%
7. Tasks issues filed and updated
8. `git push` to remote

## Files Created/Modified

### New Files
- `internal/fix/fixer.go` + `fixer_test.go`
- `internal/fix/backup.go` + `backup_test.go`
- `internal/fix/diff.go` + `diff_test.go`
- `test/fixtures/fix/multi-finding.yaml`
- `test/fixtures/fix/system-namespace.yaml`
- `test/fixtures/fix/known-workload-calico.yaml`
- `test/fixtures/fix/multi-doc-mixed.yaml`
- `test/fixtures/fix/conflict-same-field.yaml`
- `test/integration/fix_integration_test.go`

### Modified Files
- None from 3a (extend, don't modify)
