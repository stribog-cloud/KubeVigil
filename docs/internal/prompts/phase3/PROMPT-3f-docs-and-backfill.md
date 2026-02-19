# Phase 3f — Documentation: CLAUDE.md Update, README, Checker Backfill

## Context

You are completing Phase 3 of KubeVigil. **Prompts 3a through 3e are complete.** The full fix engine is implemented and tested:

- Foundation types, registry, YAML patcher, safety classification (3a)
- Core fixer orchestrator, backup, diff, conflict resolution (3b)
- CLI command with all flags, interactive confirmation, CI mode (3c)
- Kustomize, Helm values, fix report, verify, GitOps PR generators (3d)
- Comprehensive E2E test suite for fix command (3e)
- All unit, integration, and E2E tests passing

**Read these files before doing ANYTHING:**
- `CLAUDE.md` — Current version (Phase 2). You will be updating this to Phase 3.
- `README.md` — Current user-facing documentation
- `docs/internal/kubevigil-features-v3.md` **lines 561–935 only** (Section 7: Auto-Remediation Engine). For the CLAUDE.md update and README, you may need to skim the section headers of the full file, but do NOT read Sections 1–6 in detail.

This prompt (3f) handles the **final documentation updates**, CLAUDE.md transition to Phase 3 complete status, README updates, and backfilling existing checkers with FixHint data.

## Objectives

### 1. Backfill Existing Checkers with FixHint Data

The Finding struct was extended in 3a with `CurrentValue`, `DesiredValue`, and `FixHint` fields. The fix registry (3a) defines fix strategies by check ID. However, the existing checkers (Phase 1 and 2) need to be updated to **populate these fields when creating findings**.

This is a large but mechanical task. For each auto-fixable checker:

1. Open the checker file (e.g., `internal/checker/workload/privileged.go`)
2. In the `Run()` method, where `Finding` structs are created, add:
   - `CurrentValue`: the actual value found (e.g., `true` for privileged)
   - `DesiredValue`: the secure value (e.g., `false`)
   - `FieldPath`: already exists for most checkers — verify it's correct and specific enough for the patcher to locate the node
   - `FixHint`: structured fix metadata

Example (privileged checker):
```go
findings = append(findings, checker.Finding{
    Checker:     "privileged",
    Severity:    checker.Critical,
    Resource:    resource,
    Namespace:   ns,
    Kind:        kind,
    Container:   container.Name,
    Message:     "Container runs in privileged mode",
    Remediation: "Set securityContext.privileged to false",
    FieldPath:   fmt.Sprintf("spec.containers[%d].securityContext.privileged", idx),
    Frameworks:  frameworks,
    // NEW Phase 3 fields:
    CurrentValue: true,
    DesiredValue: false,
    FixHint: &checker.FixHint{
        Safety:      checker.FixSafe,
        Description: "Set privileged to false",
        Impact:      "",  // No impact — this is a safe fix
        Operation:   checker.FixOpSet,
    },
})
```

**Important rules:**
- Only add FixHint to checkers that have corresponding fix strategies in the registry
- Do NOT modify checker logic or test expectations — only add the new fields
- All existing tests MUST continue to pass
- The FixHint Safety classification must match the registry's classification
- Use subagents for parallelism — this is independent per checker category

**Priority checkers to backfill** (these have the most impactful fixes):
- Workload: privileged, capabilities-added, capabilities-not-dropped, run-as-root, read-only-rootfs, privilege-escalation, host-pid, host-ipc, host-network, host-ports, host-path-volumes, seccomp-profile, proc-mount
- Image: image-tag-latest, image-pull-policy
- RBAC: default-service-account, automount-token
- PSA: psa-labels-missing

**Checkers that should NOT get FixHint** (manual-only):
- RBAC wildcard checks (rbac-wildcard-verbs, rbac-wildcard-resources, etc.) — requires human judgment
- Network policy checks (network-policy-missing, network-policy-default-deny) — requires designing policy
- Secrets checks (secrets-in-env, secrets-in-configmap) — requires architectural change
- Cluster-level checks (etcd-encryption, audit-logging, etc.) — not manifest-fixable

### 2. Update CLAUDE.md for Phase 3

Replace the Phase 2 content in CLAUDE.md with Phase 3 completion status. The structure should be:

```markdown
# KubeVigil — CLAUDE.md

## Project Identity
(unchanged)

**Current Phase:** Phase 3 — Remediation (COMPLETE)

**Reference document:** `docs/internal/kubevigil-features-v3.md` ...

---

## Phase 1 — COMPLETE ✅
(unchanged — keep as is)

## Phase 2 — COMPLETE ✅
(condense Phase 2 to a summary like Phase 1, documenting what exists)

## Phase 3 — COMPLETE ✅
### What Exists
- `kubevigil fix` command with dry-run-by-default, --apply, --risk-level, --yes
- Five-ring safety model: dry-run default, fix classification, system NS hard block, bulk confirmation, mandatory backups
- YAML round-trip patcher preserving comments, formatting, key ordering, indentation
- Fix strategy registry for all auto-fixable checks
- System namespace detection (20+ known namespaces)
- Known system workload detection (CNI, storage operators, node exporters)
- kubectl patch generation organized by namespace
- Kustomize overlay generation (strategic merge patches)
- Helm values generation (common chart value path mapping)
- Fix report (Markdown changelog with per-file changes, skip reasons, restore instructions)
- --verify re-scan feature
- GitOps PR generation (gh/glab integration)
- Helm/Kustomize detection warnings
- CI mode detection (non-TTY, CI=true env var)
- Fix conflict resolution (merge, dedup, severity-wins)
- Multi-document YAML support
- Finding struct extended with CurrentValue, DesiredValue, FixHint
- Comprehensive E2E test suite for fix command

### Key Patterns
- Fix safety classification: Safe → Likely Safe → Potentially Breaking → Manual Only
- Risk level escalation: --apply → --risk-level moderate → --risk-level aggressive → --i-understand-system-namespaces
- Fix strategy registry: check ID → {safety, operation, field_path, desired_value}
- YAML round-trip: yaml.v3 Node API for lossless comment/format preservation

### Architecture
```
internal/fix/
├── types.go              # FixSafety, FixOp, FixHint, FixResult, FixSummary
├── registry.go           # Fix strategy registry (check → fix mapping)
├── yaml_patcher.go       # YAML round-trip node-level patcher
├── safety.go             # Safety classification, system NS detection
├── known_workloads.go    # Known system workload detection
├── fixer.go              # Fix orchestrator (Plan → Apply pipeline)
├── backup.go             # Structured backup creation
├── diff.go               # Unified diff generation
├── report.go             # Fix report (Markdown changelog)
├── kubectl_gen.go        # kubectl patch command generation
├── kustomize_gen.go      # Kustomize overlay generation
├── helm_gen.go           # Helm security values generation
└── gitops.go             # GitOps PR generation (gh/glab)
```

## Phase 4 Scope — What to Build (Next)
(placeholder for Phase 4 — CI/CD integration)

### OUT of Scope (Later Phases — Do NOT Build)
- Admission webhooks, operator mode (Phase 5)
- Multi-cluster, trend analysis (Phase 6)
- SDK, plugin system (Phase 7)

---

## Coding Standards
(unchanged from Phase 2)

## Testing Rules
(unchanged, but add Phase 3 specifics:)
- Fix integration test: scan → fix → re-scan → zero findings
- YAML round-trip tests: comment and format preservation verified
- E2E fix tests: manifest mode + live cluster mode

## Workflow Rules
(unchanged from Phase 2)

## Reminders
- **Read `docs/internal/kubevigil-features-v3.md`** (updated from v2)
- Phase 1 and 2 code is stable. Do NOT refactor.
- Fix strategies must match the registry classifications
- YAML round-trip is the hardest technical component — test thoroughly
```

### 3. Update README.md

Add the fix command to the user-facing README:

- Add `kubevigil fix` to the Commands section
- Add fix usage examples (dry-run, apply, risk levels, kubectl output, kustomize)
- Add fix safety model explanation (brief, user-facing version)
- Update feature list to include auto-remediation
- Add "Getting Started with Fix" section:
  ```
  # See what would change (safe — modifies nothing)
  kubevigil fix ./manifests/
  
  # Apply safe fixes
  kubevigil fix ./manifests/ --apply
  
  # Apply with verification
  kubevigil fix ./manifests/ --apply --verify
  
  # Generate kubectl patches instead of modifying files
  kubevigil fix ./manifests/ --output kubectl
  ```

### 4. Update Features Doc Reference

Update `docs/internal/kubevigil-features-v3.md` reference in CLAUDE.md from v2 to v3.

### 5. Final Quality Sweep

Run the complete quality gate:
1. `go test ./...` — ALL tests pass (Phase 1 + 2 + 3)
2. `go vet ./...` — clean
3. `golangci-lint run` — clean
4. `make build` — binary builds
5. Manual smoke test: `bin/kubevigil fix test/e2e/scenarios/fix-safe/` produces correct diff
6. `bats test/e2e/scripts/tests/` — all Bats tests pass
7. Check for TODO/FIXME comments that should be resolved
8. Verify all files have godoc comments

## Testing Requirements

### Checker Backfill Tests

When adding FixHint to existing checkers, verify:
1. ALL existing tests still pass without modification
2. New findings include FixHint with correct safety classification
3. CurrentValue and DesiredValue are populated for fixable checks
4. FieldPath is specific enough for the YAML patcher to locate the node
5. Run the scan → fix → re-scan integration test to verify the full pipeline works with backfilled checkers

### Documentation Verification

- CLAUDE.md is self-consistent (no references to outdated Phase 2 content in Phase 3 sections)
- README examples actually work when copy-pasted
- Features v3 Section 7 matches the actual implementation

## Tasks Integration

File issues:
- `phase3-checker-backfill-workload` — Backfill FixHint for workload checkers
- `phase3-checker-backfill-image` — Backfill FixHint for image checkers
- `phase3-checker-backfill-rbac` — Backfill FixHint for RBAC checkers (SA checks only)
- `phase3-checker-backfill-psa` — Backfill FixHint for PSA checkers
- `phase3-claude-md-update` — Update CLAUDE.md to Phase 3
- `phase3-readme-update` — Update README.md with fix documentation
- `phase3-final-quality-sweep` — Final verification pass

## Quality Gates

1. `go test ./...` passes (ALL tests — this is the most critical gate)
2. `go vet ./...` clean
3. `golangci-lint run` clean
4. `make build` succeeds
5. Smoke test: `bin/kubevigil fix` works on sample fixtures
6. All Bats tests pass
7. CLAUDE.md accurately reflects current state
8. README fix examples are correct
9. ALL tasks issues closed or carried to Phase 4
10. `git push` to remote

## Files Created/Modified

### Modified Files (Checker Backfill)
- `internal/checker/workload/privileged.go` — Add FixHint
- `internal/checker/workload/capabilities.go` — Add FixHint
- `internal/checker/workload/run_as_root.go` — Add FixHint
- `internal/checker/workload/read_only_rootfs.go` — Add FixHint
- `internal/checker/workload/privilege_escalation.go` — Add FixHint
- (... and ~15 more workload checkers)
- `internal/checker/image/image_tag_latest.go` — Add FixHint
- `internal/checker/image/image_pull_policy.go` — Add FixHint
- `internal/checker/rbac/default_service_account.go` — Add FixHint
- `internal/checker/rbac/automount_token.go` — Add FixHint
- `internal/checker/psa/psa_labels_missing.go` — Add FixHint

### Modified Files (Documentation)
- `CLAUDE.md` — Update to Phase 3 complete
- `README.md` — Add fix command documentation

### No New Files
This prompt only modifies existing files. All new files were created in 3a-3e.
