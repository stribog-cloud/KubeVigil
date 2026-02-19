# KubeVigil — CLAUDE.md

## Project Identity

**KubeVigil** — "Know your clusters before attackers do."

A Kubernetes Security Posture Management (KSPM) CLI tool written in Go. Open source, Apache 2.0 licensed, built by Stribog. This is also a Go learning project — the codebase should teach idiomatic Go patterns through real-world production code.

**Current Phase:** Phase 3 — Remediation

**Reference document:** `docs/internal/kubevigil-features-v3.md` contains the complete feature specification across all 7 phases, including the full auto-remediation engine design. **Read this file before making architectural decisions.** Section 7 is the authoritative spec for Phase 3.

---

## Phase 1 — COMPLETE ✅

Phase 1 built the foundation: 25 workload security checkers, scan engine (live + manifest modes), text + JSON output, CLI (scan/list/version), configuration system with exemptions, and comprehensive test infrastructure. **Do not rebuild or restructure Phase 1 code** — extend it.

### Key Patterns Established (Follow These)

- **Checker pattern:** One file + one test file per check in `internal/checker/<category>/`. Table-driven tests with 15+ cases. Checkers use `ExtractPodSpecs` + `IterateContainers` for workload checks.
- **Registration pattern:** Each category package has `register.go` with `init()` registering all checkers.
- **Fixture pattern:** `test/fixtures/<check-id>/` with passing and failing YAML files.
- **Test helper pattern:** `test/helpers/` has generators (functional options), assertions, fixture loaders.
- **Contract test pattern:** `test/integration/contract_test.go` iterates ALL registered checkers and verifies interface compliance.

---

## Phase 2 — COMPLETE ✅

Phase 2 expanded to 110 security checks across 12 categories, 8 output formats, and 3 compliance framework mappings. **Do not rebuild or restructure Phase 2 code** — extend it.

### What Exists

- **110 security checks** across 12 categories: workload (25), image (9), RBAC (15), secrets (7), network (12), PSA (6), scheduling (8), storage (5), cluster (10), supply chain (5), cloud (4), CRD (4)
- **Dual-mode scanning:** Live cluster (API) and manifest (YAML/JSON files, directories, multi-doc). 94 checks work in both modes, 15 live-only, 1 manifest-only.
- **8 output formats:** Text (colored terminal), JSON, YAML, Markdown, HTML (self-contained), SARIF 2.1.0, JUnit XML, CSV
- **3 compliance frameworks:** CIS Kubernetes Benchmark v1.8, MITRE ATT&CK v14, NSA/CISA Hardening Guide v1.2 — every check mapped to at least one framework
- **Configuration:** `.kubevigil.yaml` with check enable/disable, severity overrides, exemptions (namespace/resource/kind/annotation with expiry)
- **CLI:** `kubevigil scan` (--file for manifest, live cluster default), `kubevigil list checks`, `kubevigil version`
- **Exit codes:** 0 (clean), 1 (findings), 2 (scan error), 3 (config error), 4 (partial scan)
- **Structured logging:** `log/slog` throughout

### Architecture

```
internal/checker/
├── workload/        # 25 checks — container security context
├── image/           # 9 checks — image tag, digest, registry, signatures
├── rbac/            # 15 checks — ServiceAccount, Roles, Bindings
├── secrets/         # 7 checks — env secrets, encryption, entropy
├── network/         # 12 checks — NetworkPolicy, Ingress, Service, mesh
├── psa/             # 6 checks — PSA labels, PSS profiles
├── scheduling/      # 8 checks — tolerations, priority, PDB, HPA
├── storage/         # 5 checks — PVC, CSI, emptyDir
├── cluster/         # 10 checks — namespace, quotas, API server, etcd
├── supply_chain/    # 5 checks — runtime sockets, probes, image age
├── cloud/           # 4 checks — EKS, GKE, AKS, auto-detect
└── crd/             # 4 checks — CRD validation, cert-manager

internal/config/     # Config loading, exemptions, namespace filtering
internal/engine/     # Scan orchestration, manifest parser
internal/frameworks/ # CIS, MITRE, NSA mapping
internal/k8s/        # Kubernetes client wrapper
internal/report/     # 8 output formatters with contract tests
internal/version/    # Build version
cmd/kubevigil/       # CLI (scan, list, version commands)
```

---

## Phase 3 Scope — What to Build

### Design Philosophy

**Safe by default.** `kubevigil fix` without `--apply` modifies nothing — it shows a diff. Every layer of danger requires an additional explicit opt-in. Ignorant users are protected from destroying things unintentionally. Knowledgeable operators can unlock full power through explicit flags.

**The fix command operates on manifests, not live objects.** It generates artifacts (patched manifests, kubectl commands, Kustomize overlays, Helm values) that operators apply through their existing deployment workflows. The tool NEVER directly patches a live cluster.

### IN Scope

#### Core Fix Engine

| Component | File | Description |
|-----------|------|-------------|
| Fix types | `internal/fix/types.go` | FixSafety, FixOp, FixHint, FixResult, FixSummary, FixError, FixConfig |
| Fix registry | `internal/fix/registry.go` | Check ID → fix strategy mapping for all auto-fixable checks |
| YAML patcher | `internal/fix/yaml_patcher.go` | Round-trip YAML manipulation via yaml.v3 Node API — preserves comments, formatting, key ordering, indentation |
| Safety classification | `internal/fix/safety.go` | System namespace detection, risk level filtering |
| Known workloads | `internal/fix/known_workloads.go` | CNI, storage operator, node exporter detection by image pattern |
| Fixer orchestrator | `internal/fix/fixer.go` | Scan → Filter → Classify → Gate → Plan → Backup → Patch → Verify pipeline |
| Backup system | `internal/fix/backup.go` | Structured backup directory with RESTORE.md |
| Diff generation | `internal/fix/diff.go` | Unified diff with ANSI color for TTY |

#### CLI Command

| Component | File | Description |
|-----------|------|-------------|
| Fix command | `cmd/kubevigil/fix.go` | `kubevigil fix` Cobra command with all flags |
| kubectl generator | `internal/fix/kubectl_gen.go` | kubectl patch command generation organized by namespace |

#### Output Generators

| Component | File | Description |
|-----------|------|-------------|
| Kustomize generator | `internal/fix/kustomize_gen.go` | Strategic merge patch overlay generation |
| Helm generator | `internal/fix/helm_gen.go` | security-values.yaml for common chart patterns |
| Fix report | `internal/fix/report.go` | Markdown changelog with per-file changes and restore instructions |
| GitOps PR | `internal/fix/gitops.go` | Branch + commit + PR via gh/glab CLI |

#### Finding Struct Extension

Backward-compatible extension to `internal/checker/checker.go`:

```go
type Finding struct {
    // ... ALL existing fields unchanged ...
    CurrentValue interface{} `json:"current_value,omitempty" yaml:"current_value"`
    DesiredValue interface{} `json:"desired_value,omitempty" yaml:"desired_value"`
    FixHint      *FixHint    `json:"fix_hint,omitempty" yaml:"fix_hint"`
}
```

Existing checkers that don't populate these fields continue working. All Phase 1/2 tests MUST pass unchanged.

### OUT of Scope (Later Phases — Do NOT Build)

- Distribution: GoReleaser, GitHub Releases, Homebrew, Krew, Docker, install script (Phase 4)
- Feedback, hardening & polish: real-world testing, severity calibration, bug fixes (Phase 5)
- GitHub Action, baseline management, PR decoration, incremental scanning (Phase 6)
- Admission webhooks, operator mode, Prometheus metrics, Grafana (Phase 7)
- Multi-cluster, trend analysis, SQLite, Rego policies (Phase 8)
- SDK, plugin system, docs site, Helm chart (Phase 9)
- Attack path analysis, posture scoring, scan caching
- PDF output

---

## Phase 3 Architecture

### Five-Ring Safeguard Model

Every layer of danger requires an additional explicit opt-in:

| Ring | Protection | How |
|------|-----------|-----|
| 1 | Dry-run by default | `kubevigil fix` without `--apply` modifies nothing |
| 2 | Fix safety classification | `--apply` only does Safe fixes. `--risk-level moderate` adds Likely Safe. `--risk-level aggressive` adds Potentially Breaking. |
| 3 | System namespace hard block | System namespaces NEVER auto-fixed. Requires `--i-understand-system-namespaces`. |
| 4 | Interactive confirmation | Bulk operations (>10 files) require confirmation. Safe defaults (Review? Y, Apply? N). `--yes` bypasses. |
| 5 | Mandatory backup | Every fix creates backup with RESTORE.md. Restore command printed after every operation. |

### Fix Safety Classifications

| Classification | Risk | Auto-apply at | Examples |
|---------------|------|---------------|----------|
| **Safe** | Zero | `--apply` | `privileged: false`, `allowPrivilegeEscalation: false`, `automountServiceAccountToken: false` |
| **Likely Safe** | Very low | `--risk-level moderate` | `drop: ["ALL"]`, `runAsNonRoot: true`, `readOnlyRootFilesystem: true` |
| **Potentially Breaking** | Could break functionality | `--risk-level aggressive` | Default resource limits, remove hostPort |
| **Manual Only** | Cannot auto-fix | Never (guidance only) | RBAC restructuring, NetworkPolicy creation, secrets architecture |

### Risk Level Escalation Path

```
kubevigil fix ./manifests/                          # See diff only (Ring 1)
kubevigil fix ./manifests/ --apply                  # Safe fixes only (Ring 2)
kubevigil fix ./manifests/ --apply --risk-level moderate   # + Likely Safe (Ring 2)
kubevigil fix ./manifests/ --apply --risk-level aggressive # + Potentially Breaking (Ring 2)
kubevigil fix ./manifests/ --apply --risk-level aggressive --i-understand-system-namespaces  # + System NS (Ring 3)
```

### Partial Failure Resilience

The fixer is per-file resilient. When file 150 of 200 fails (malformed YAML, permission denied, unexpected structure), the fixer continues with remaining files and collects errors. **No all-or-nothing behavior.** Already-patched files are NOT rolled back. Exit code 5 for partial success.

### Fix Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Fix successful — all planned fixes applied (or dry-run shows changes) |
| `1` | Fix applied but `--verify` found remaining findings |
| `2` | Fix error — total failure (backup failed, no files could be processed) |
| `3` | Configuration error (invalid flags, conflicting options) |
| `4` | No fixable findings found (nothing to do) |
| `5` | Partial success — some fixes applied but N files failed |

### YAML Round-Trip Patcher

The single hardest technical challenge. Uses `gopkg.in/yaml.v3` Node API for lossless manipulation:

- **Preserves:** comments (inline, head, foot), blank lines, key ordering, indentation style (2/4-space), quoting style
- **Operations:** FindNode (navigate by path), SetNode, AddNode, RemoveNode
- **Multi-document:** Parse each `---` document separately, fix only affected documents, reassemble with original separators
- **NEVER use** marshal/unmarshal (encoding/decoding) for round-trip — it destroys formatting

### Known System Workloads

The fix engine detects and skips known system workloads that legitimately need elevated privileges:

- **CNI plugins:** Calico, Cilium, Flannel — need hostNetwork, privileged
- **Storage operators:** Rook-Ceph, Longhorn, OpenEBS — need privileged, hostPath
- **Node exporters:** Prometheus — need hostPID, hostNetwork
- **Core components:** kube-proxy, CoreDNS — need specific capabilities

Detection by image name patterns and well-known labels.

### Config File Integration

The existing `.kubevigil.yaml` supports fix-specific settings:

```yaml
fix:
  additionalSystemNamespaces:    # Extends (never replaces) built-in defaults
    - "custom-infra"
    - "vault"
  bulkThreshold: 20              # Override confirmation threshold (default: 10)
  backupDir: "/tmp/kubevigil-backups/"  # Default backup directory
```

CLI flags always override config file values.

### Inline "What Could Break" Warnings

Dry-run diff output includes impact warnings directly below the relevant change for likely_safe and potentially_breaking fixes. Users see risk information at the point of change, not buried in a separate report.

### CI Mode

Detected by `CI=true`, `GITHUB_ACTIONS=true`, `GITLAB_CI=true`, `JENKINS_URL` set, or non-TTY stdin. `--apply` without `--yes` fails immediately with guidance. With `--apply --yes`, proceeds but prints full summary to stdout.

---

## Phase 3 File Structure

### New Files

```
internal/fix/
├── types.go + _test.go           # Fix types, safety, operations
├── registry.go + _test.go        # Check → fix strategy mapping
├── yaml_patcher.go + _test.go    # YAML round-trip node manipulation
├── safety.go + _test.go          # System NS detection, risk filtering
├── known_workloads.go + _test.go # System workload detection
├── fixer.go + _test.go           # Fix orchestrator pipeline
├── backup.go + _test.go          # Structured backup creation
├── diff.go + _test.go            # Unified diff generation
├── report.go + _test.go          # Fix report (Markdown changelog)
├── kubectl_gen.go + _test.go     # kubectl patch generation
├── kustomize_gen.go + _test.go   # Kustomize overlay generation
├── helm_gen.go + _test.go        # Helm values generation
└── gitops.go + _test.go          # GitOps PR generation

cmd/kubevigil/
├── fix.go + fix_test.go          # kubevigil fix command
└── root.go                       # Modified: register fix command

test/fixtures/fix/                # Fix-specific test fixtures
test/integration/fix_*_test.go    # Fix integration tests

test/e2e/scenarios/
├── fix-safe/                     # Safe fixes E2E
├── fix-moderate/                 # Risk level gating E2E
├── fix-aggressive/               # Aggressive fixes E2E
├── fix-system-ns/                # System NS protection E2E
├── fix-known-workloads/          # Known workload detection E2E
├── fix-multi-doc/                # Multi-document YAML E2E
├── fix-comments/                 # Comment preservation E2E
├── fix-partial-failure/          # Partial failure resilience E2E
└── fix-clean/                    # Clean scenario (nothing to fix)

test/e2e/scripts/
├── run-fix.sh                    # Manifest-mode fix E2E
├── run-fix-live.sh               # Live cluster fix E2E (Kind)
└── tests/fix.bats                # 18 Bats tests
```

### Modified Files

```
internal/checker/checker.go         # Finding struct extension (backward-compatible)
internal/checker/workload/*.go      # FixHint backfill (~15 files)
internal/checker/image/*.go         # FixHint backfill (~2 files)
internal/checker/rbac/*.go          # FixHint backfill (SA checks only)
internal/checker/psa/*.go           # FixHint backfill (~1 file)
cmd/kubevigil/root.go               # Register fix command
CLAUDE.md                           # Update to Phase 3 complete (at end)
README.md                           # Add fix command documentation
test/e2e/README.md                  # Document fix E2E tests
```

---

## Coding Standards

### Go Standards (Unchanged)

- **Go 1.22+**, module `github.com/stribog-cloud/kubevigil`
- `gofmt` + `goimports`, `golangci-lint`
- Wrap errors: `fmt.Errorf("loading config: %w", err)`
- `log/slog` for logging. No `fmt.Println`.
- Godoc comments on all exported types/functions
- Minimize dependencies. Standard library preferred.

### Phase 3 Dependencies

- `gopkg.in/yaml.v3` — YAML round-trip via Node API. Check if already in go.mod before adding.
- `golang.org/x/term` — TTY detection for interactive confirmation. Evaluate if `os.Stdin.Stat()` suffices first.
- No other new dependencies without justification.

### Code Organization Rules (Unchanged)

- One file + one test file per component
- Test fixtures in `test/fixtures/fix/`
- Contract tests verify interface compliance

---

## Testing Rules (Non-Negotiable)

### TDD is mandatory. Red → Green → Refactor.

For EVERY file, write the test FIRST, watch it fail, then implement.

### Phase 3 Test Additions

- **YAML round-trip tests** — Parse → serialize → byte-for-byte match for simple cases. Comment preservation verified. Key ordering preserved. Multi-document handling correct.
- **Fix integration test** — Scan → Fix → Re-scan → Zero findings (the golden workflow). MUST pass.
- **Partial failure tests** — Malformed YAML, permission denied files don't crash the fixer. Other files still patched.
- **Safety classification tests** — Risk level gating verified. System namespace hard block verified. Known workload detection verified.
- **Inline warning tests** — Dry-run diff includes "What Could Break" for non-safe fixes.
- **Exit code tests** — All six fix exit codes (0-5) verified.
- **Backward compatibility** — ALL Phase 1 and Phase 2 tests pass unchanged after Finding struct extension.
- **E2E golden workflow** — scan → fix → re-scan → zero findings with comment preservation. If this breaks, Phase 3 is not shippable.

### Coverage Targets

- Line coverage for new code: ≥ 85%
- All fix components have unit tests
- Integration test for full pipeline
- 18 Bats E2E tests
- Live cluster E2E via Kind

---

## Workflow Rules (Unchanged)

### Planning
- Plan mode for ANY non-trivial task
- Stop and re-plan if something goes sideways

### Parallel Execution
- Use subagents for independent components
- Use agent teams for cross-cutting work (checker backfill)
- Lead orchestrates, does NOT write code

### Task Tracking (Tasks)
```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --status in_progress
bd close <id>
bd sync
```

### Session Completion
1. File tasks issues for remaining work
2. Quality gates: `go test ./...`, `go vet ./...`, `golangci-lint run`
3. Update tasks status
4. **Push to remote — MANDATORY:**
   ```bash
   git pull --rebase
   bd sync
   git push
   git status  # Must show "up to date with origin"
   ```
5. Provide context for next session

**Work is NOT complete until `git push` succeeds.**

### Self-Improvement
- After ANY correction: tasks issue with `lesson` label
- Review lessons at session start

---

## Key Decisions (Pre-Made)

All Phase 1 and Phase 2 decisions remain. Additional for Phase 3:

- **Dry-run by default.** The `--apply` flag is required to modify files. This is non-negotiable.
- **YAML round-trip via yaml.v3 Node API.** Never marshal/unmarshal for round-trip operations. Preserve all comments and formatting.
- **No live cluster patching.** The fix command generates artifacts only. kubectl commands are generated text, never executed.
- **System namespace protection is a hard block.** The `--i-understand-system-namespaces` flag name is intentionally long and awkward. Do not shorten it.
- **Risk levels are additive.** `moderate` includes `safe` + `likely_safe`. `aggressive` includes all three. There is no way to apply only `potentially_breaking` without also applying safe fixes.
- **Partial failure is expected.** The fixer continues on per-file errors. Exit code 5 for partial success.
- **Backup is mandatory.** Every `--apply` creates a backup. There is no `--no-backup` flag.
- **Config additionalSystemNamespaces is additive.** Users can add to the built-in list, never remove from it.
- **Fix strategies are registered centrally.** The registry is the single source of truth for which checks are auto-fixable and their safety classification.
- **Checker backfill is backward-compatible.** Adding FixHint to existing checkers must not change any existing test expectations.

---

## Implementation Order — Phase 3

Phase 3 is implemented via 6 sequential prompts in `docs/internal/prompts/phase3/`:

| Prompt | Scope | Depends On |
|--------|-------|-----------|
| **3a** — Foundation | Types, Finding extension, Fix registry, YAML round-trip, Safety classification | — |
| **3b** — Core Engine | Fixer orchestrator, Backup, Diff, Conflict resolution, Partial failure | 3a |
| **3c** — CLI Command | `kubevigil fix`, Dry-run default, Risk levels, Interactive confirmation, CI mode, Config integration | 3b |
| **3d** — Output Generators | Kustomize, Helm values, Fix report, Verify, GitOps PR, Detection warnings | 3c |
| **3e** — E2E Testing | 9 fix scenarios, Bats tests, run-fix.sh, run-fix-live.sh, Golden workflow | 3d |
| **3f** — Docs & Backfill | Checker FixHint backfill, CLAUDE.md update, README update, Final quality sweep | 3e |

Each prompt is self-contained. Execute in order. See `docs/internal/prompts/phase3/README.md` for the full overview.

---

## Reminders

- **Read `docs/internal/kubevigil-features-v3.md` Section 7** for the complete auto-remediation spec. This CLAUDE.md summarizes the architecture but the features doc has the full behavioral specification, edge cases, and output examples.
- **YAML round-trip is the hardest technical piece.** Test it obsessively. Comments, blank lines, key ordering, indentation style, quoting style — all must survive.
- **The golden workflow must always pass:** scan → fix → re-scan → zero findings.
- **Phase 1 and Phase 2 code is stable.** Don't refactor it unless you find a bug. Extend, don't rewrite.
- **The Finding struct extension is backward-compatible.** Existing checkers that don't populate new fields continue working. ALL existing tests must pass unchanged.
- **System namespace protection is non-negotiable.** An ignorant user who runs `kubevigil fix --apply` must not be able to break their cluster's networking, storage, or core services.
