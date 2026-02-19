# Phase 3 — Auto-Remediation: Implementation Plan

## Overview

Phase 3 adds `kubevigil fix` — an auto-remediation engine that patches Kubernetes YAML manifests to resolve security findings. The design philosophy is **safe by default**: dry-run is the default mode, every layer of danger requires an additional explicit opt-in, and ignorant users are protected from destroying things unintentionally.

## Design Document

`docs/internal/kubevigil-features-v3.md` — Complete feature specification. Section 7 contains the full auto-remediation engine design. **Read this before starting any prompt.**

## Prompt Breakdown

Phase 3 is broken into 6 sequential prompts. Each prompt is self-contained and builds on the previous ones. Execute them in order.

| Prompt | Title | Scope | Estimated Effort |
|--------|-------|-------|-----------------|
| **3a** | Foundation | Types, Finding extension, Fix registry, YAML round-trip, Safety classification | 1 session |
| **3b** | Core Engine | Fixer orchestrator, YAML patcher, Backup system, Diff, Conflict resolution | 1-2 sessions |
| **3c** | CLI Command | `kubevigil fix` command, Dry-run default, Risk levels, Interactive confirmation, CI mode | 1 session |
| **3d** | Output Generators | Kustomize overlay, Helm values, Fix report, Verify, GitOps PR | 1-2 sessions |
| **3e** | E2E Testing | Fix E2E scenarios, Scan→Fix→Verify workflow, Bats tests, Live cluster tests | 1-2 sessions |
| **3f** | Docs & Backfill | Checker FixHint backfill, CLAUDE.md update, README update, Final quality sweep | 1 session |

**Total estimated: 6-9 sessions**

## Dependency Graph

```
3a (Foundation)
  └── 3b (Core Engine)
        └── 3c (CLI Command)
              └── 3d (Output Generators)
                    └── 3e (E2E Testing)
                          └── 3f (Docs & Backfill)
```

Each prompt requires the previous to be complete. No parallelism between prompts (within a prompt, subagents can parallelize).

## Key Design Decisions

1. **Dry-run by default** — `kubevigil fix` without `--apply` modifies nothing
2. **Risk levels** — safe (default), moderate (`--risk-level moderate`), aggressive (`--risk-level aggressive`)
3. **System namespace hard block** — Requires `--i-understand-system-namespaces` flag
4. **YAML round-trip** — gopkg.in/yaml.v3 Node API for lossless comment/format preservation
5. **No live cluster patching** — Fix generates artifacts (patched manifests, kubectl commands, overlays), never directly patches live objects
6. **Backward compatible** — Finding struct extension is additive; all Phase 1/2 tests pass unchanged

## Development Protocol

All prompts follow the established KubeVigil development protocol:

- **TDD mandatory** — Red → Green → Refactor. Tests first.
- **Tasks tracking** — File issues for each component, track status
- **Subagents** — Use for independent tasks within a prompt
- **Quality gates** — `go test ./...`, `go vet ./...`, `golangci-lint run`, `git push`
- **Git discipline** — Push to remote at the end of each prompt session

## Files Inventory

### New Files (across all prompts)

```
internal/fix/
├── types.go + _test.go           # 3a
├── registry.go + _test.go        # 3a
├── yaml_patcher.go + _test.go    # 3a
├── safety.go + _test.go          # 3a
├── known_workloads.go + _test.go # 3a
├── fixer.go + _test.go           # 3b
├── backup.go + _test.go          # 3b
├── diff.go + _test.go            # 3b
├── report.go + _test.go          # 3d
├── kubectl_gen.go + _test.go     # 3c
├── kustomize_gen.go + _test.go   # 3d
├── helm_gen.go + _test.go        # 3d
└── gitops.go + _test.go          # 3d

cmd/kubevigil/
└── fix.go + fix_test.go          # 3c

test/fixtures/fix/                # 3a, 3b
test/integration/fix_*_test.go    # 3b

test/e2e/scenarios/
├── fix-safe/                     # 3e
├── fix-moderate/                 # 3e
├── fix-aggressive/               # 3e
├── fix-system-ns/                # 3e
├── fix-known-workloads/          # 3e
├── fix-multi-doc/                # 3e
├── fix-comments/                 # 3e
├── fix-partial-failure/          # 3e
└── fix-clean/                    # 3e

test/e2e/scripts/
├── run-fix.sh                    # 3e
├── run-fix-live.sh               # 3e
└── tests/fix.bats                # 3e
```

### Modified Files

```
internal/checker/checker.go       # 3a (Finding struct extension)
internal/checker/workload/*.go    # 3f (FixHint backfill)
internal/checker/image/*.go       # 3f (FixHint backfill)
internal/checker/rbac/*.go        # 3f (FixHint backfill, SA checks)
internal/checker/psa/*.go         # 3f (FixHint backfill)
cmd/kubevigil/root.go             # 3c (register fix command)
CLAUDE.md                         # 3f (Phase 3 complete)
README.md                         # 3f (fix documentation)
test/e2e/README.md                # 3e (fix E2E docs)
test/e2e/expected/README.md       # 3e (fix expected findings)
test/e2e/scripts/validate-findings.py  # 3e (fix validation mode)
```

## Success Criteria

Phase 3 is complete when:

1. `kubevigil fix ./path/` shows a diff without modifying anything
2. `kubevigil fix ./path/ --apply` applies safe fixes with backup
3. Risk level gating works: safe → moderate → aggressive
4. System namespaces are protected by default
5. Known system workloads are detected and skipped
6. `--output kubectl` generates valid kubectl patch commands
7. `--kustomize` generates a valid Kustomize overlay
8. `--output helm-values` generates valid Helm values
9. `--verify` re-scans and confirms fixes resolved findings
10. `--git-pr` creates a branch and PR
11. YAML comments and formatting are preserved through fix
12. Multi-document YAML files handled correctly
13. E2E golden workflow passes: scan → fix → re-scan → zero findings
14. All Phase 1/2/3 tests pass: `go test ./...`
15. CLAUDE.md and README updated
