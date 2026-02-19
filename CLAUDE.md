# KubeVigil — CLAUDE.md

## Project Identity

**KubeVigil** — "Know your clusters before attackers do."

A Kubernetes Security Posture Management (KSPM) CLI tool written in Go. Open source, Apache 2.0 licensed, built by Stribog. This is also a Go learning project — the codebase should teach idiomatic Go patterns through real-world production code.

**Current Phase:** Phase 1 — Foundation (MVP)

**Reference document:** `docs/kubevigil-features-v2.md` contains the complete feature specification across all 7 phases. **Read this file before making architectural decisions.** It defines the full checker interface, all 112 security checks, testing strategy, directory structure, and roadmap. You are implementing Phase 1 only — do not build features from later phases.

---

## Phase 1 Scope — What to Build

### IN Scope

1. **Core scanning engine** — Resource cache, checker interface, checker registry, concurrent execution via errgroup
2. **Scan modes** — Live cluster scan (kubeconfig) and manifest scan (YAML files/directories from disk)
3. **24 workload security checks** — All checks from Section 2.1 of the features doc (privileged through share-process-namespace)
4. **3 container lifecycle checks** — Section 2.2 (init-container-security, sidecar-container-security, ephemeral-container-policy)
5. **Output formats** — Text (colored terminal) and JSON
6. **CLI** — `kubevigil scan` (live cluster), `kubevigil scan --file <path>` (manifest mode), `kubevigil list checks`, `kubevigil version`
7. **Basic config** — `.kubevigil.yaml` with check enable/disable, severity overrides, and exemptions (namespace + annotation-based)
8. **Exit codes** — 0 (clean), 1 (findings above threshold), 2 (scan error), 3 (config error)
9. **Full TDD test suite** — Unit tests, contract tests, test fixtures, test helpers

### OUT of Scope (Later Phases — Do NOT Build)

- Helm chart scanning, Kustomize scanning, stdin scanning, multi-cluster, diff scan, watch mode
- RBAC checks, network checks, secrets checks, image checks, cloud provider checks, CRD checks, storage checks, scheduling checks, cluster config checks, supply chain checks (all Phase 2+)
- HTML, Markdown, SARIF, JUnit, CSV, YAML, PDF output (Phase 2+)
- Auto-remediation / `kubevigil fix` (Phase 3)
- GitHub Action, baseline management, PR decoration (Phase 4)
- Admission webhooks, operator mode, Prometheus metrics (Phase 5)
- Trend analysis, multi-cluster, Rego policies (Phase 6)
- SDK, plugin system, docs site (Phase 7)

---

## Architecture

### Checker Interface (Central Design)

This is the most important abstraction. Every security check implements this interface. Get this right — everything else flows from it.

```go
type Checker interface {
    Name() string                                              // kebab-case: "privileged"
    Description() string                                       // Human-readable
    Categories() []Category                                    // e.g., CategoryWorkload
    SupportedModes() []ScanMode                                // ScanModeLive, ScanModeManifest
    RequiredResources() []schema.GroupVersionResource           // What K8s resources this check needs
    Run(ctx context.Context, resources *ResourceCache) ([]Finding, error)
}
```

### Key Types

```go
type Severity int
const (
    SeverityInfo Severity = iota
    SeverityLow
    SeverityMedium
    SeverityHigh
    SeverityCritical
)

type Finding struct {
    Checker      string    // Check ID that produced this finding
    Severity     Severity
    Resource     string    // Resource name
    Namespace    string
    Kind         string    // Deployment, Pod, StatefulSet, etc.
    Container    string    // Container name (if applicable)
    Message      string    // Human-readable description of the issue
    Remediation  string    // How to fix it
    FieldPath    string    // e.g., ".spec.containers[0].securityContext.privileged"
}

type ScanResult struct {
    Findings     []Finding
    ClusterInfo  ClusterInfo  // K8s version, node count, etc.
    ScanMeta     ScanMeta     // Timestamp, duration, checks run/skipped
}
```

### Resource Cache

A shared, read-only, thread-safe cache of fetched Kubernetes resources:
- Populated once per scan based on the union of all enabled checks' `RequiredResources()`
- All checkers read from the same cache concurrently
- For live scans: fetches from K8s API via client-go
- For manifest scans: populated by parsing YAML files
- Handles graceful degradation: if RBAC denies access to a resource type, log warning, skip affected checks

### Checker Registry

Central registry where all checkers self-register via Go `init()` functions. The scan engine asks the registry for all enabled checks, collects their `RequiredResources()`, populates the cache, then runs all checks concurrently via `errgroup`.

### Directory Structure (Phase 1)

```
kubevigil/
├── cmd/kubevigil/
│   ├── main.go                          # Entry point
│   ├── root.go                          # Root cobra command
│   ├── scan.go                          # kubevigil scan command
│   ├── list.go                          # kubevigil list checks
│   └── version.go                       # kubevigil version
├── internal/
│   ├── checker/
│   │   ├── checker.go                   # Checker interface, Finding, Severity types
│   │   ├── registry.go                  # Checker registry (registration + lookup)
│   │   ├── registry_test.go
│   │   ├── category.go                  # Category enum
│   │   ├── contract_test.go             # Contract tests for ALL checkers
│   │   └── workload/                    # Phase 1: all workload checks here
│   │       ├── privileged.go
│   │       ├── privileged_test.go
│   │       ├── capabilities.go
│   │       ├── capabilities_test.go
│   │       ├── run_as_root.go
│   │       ├── run_as_root_test.go
│   │       ├── ... (one file + one test file per check)
│   │       └── register.go             # init() function to register all workload checks
│   ├── engine/
│   │   ├── scanner.go                   # Scan orchestrator
│   │   ├── scanner_test.go
│   │   ├── resource_cache.go            # Resource cache (shared, read-only)
│   │   ├── resource_cache_test.go
│   │   ├── manifest_parser.go           # YAML file/directory parsing
│   │   └── manifest_parser_test.go
│   ├── k8s/
│   │   ├── client.go                    # client-go initialization
│   │   └── client_test.go
│   ├── report/
│   │   ├── reporter.go                  # Reporter interface
│   │   ├── text.go                      # Colored terminal output
│   │   ├── text_test.go
│   │   ├── json.go                      # JSON output
│   │   ├── json_test.go
│   │   └── contract_test.go             # Contract tests for ALL reporters
│   ├── config/
│   │   ├── config.go                    # Config struct + parsing
│   │   ├── config_test.go
│   │   ├── exemptions.go               # Exemption matching logic
│   │   └── exemptions_test.go
│   └── version/
│       └── version.go                   # Build version info (ldflags)
├── test/
│   ├── fixtures/                        # YAML fixtures organized per check
│   │   ├── privileged/
│   │   │   ├── pod-privileged-true.yaml
│   │   │   ├── pod-privileged-false.yaml
│   │   │   ├── deployment-privileged.yaml
│   │   │   └── ...
│   │   ├── capabilities/
│   │   ├── run-as-root/
│   │   └── ... (one directory per check)
│   ├── golden/                          # Golden file outputs for report tests
│   │   ├── text-report.txt
│   │   └── json-report.json
│   ├── helpers/
│   │   ├── fixture_loader.go            # LoadFixture(), LoadFixtureRaw()
│   │   ├── assertions.go               # AssertFinding(), AssertNoFindings()
│   │   └── generators.go               # GenerateDeployment(), GeneratePod(), WithPrivileged(), etc.
│   └── integration/
│       ├── scan_manifest_test.go        # Full scan pipeline: directory → findings → report
│       └── config_exemptions_test.go    # Config + exemptions integration
├── configs/
│   └── kubevigil.example.yaml           # Example config file
├── docs/
│   └── kubevigil-features-v2.md         # Full feature specification (reference)
├── go.mod
├── go.sum
├── Makefile
├── .golangci.yml
├── .gitignore
├── LICENSE                              # Apache 2.0
├── README.md
└── CLAUDE.md                            # This file
```

---

## Phase 1 Checks — Complete List

Implement ALL of these. Each check = one file + one test file in `internal/checker/workload/`.

| # | Check ID | What It Detects | Severity |
|---|----------|----------------|----------|
| 1 | `privileged` | `privileged: true` in securityContext | Critical |
| 2 | `capabilities-added` | Dangerous capabilities added (SYS_ADMIN, NET_RAW, SYS_PTRACE, etc.) | High |
| 3 | `capabilities-not-dropped` | Not dropping ALL capabilities | Medium |
| 4 | `run-as-root` | Running as root (UID 0) or missing `runAsNonRoot: true` | High |
| 5 | `run-as-high-uid` | UID < 10000 | Low |
| 6 | `run-as-group` | Missing runAsGroup or GID 0 | Medium |
| 7 | `read-only-rootfs` | Missing `readOnlyRootFilesystem: true` | Medium |
| 8 | `resource-limits-missing` | Missing CPU or memory limits | Medium |
| 9 | `resource-requests-missing` | Missing CPU or memory requests | Medium |
| 10 | `resource-limits-ratio` | Limits-to-requests ratio > threshold | Low |
| 11 | `ephemeral-storage-limits` | Missing ephemeral-storage limits | Low |
| 12 | `host-pid` | `hostPID: true` | Critical |
| 13 | `host-ipc` | `hostIPC: true` | Critical |
| 14 | `host-network` | `hostNetwork: true` | Critical |
| 15 | `host-ports` | Containers binding host ports | High |
| 16 | `host-path-volumes` | hostPath volume mounts (severity by path) | Critical-Medium |
| 17 | `privilege-escalation` | Missing `allowPrivilegeEscalation: false` | High |
| 18 | `seccomp-profile` | Missing Seccomp profile | Medium |
| 19 | `apparmor-profile` | Missing AppArmor profile | Medium |
| 20 | `selinux-options` | SELinux misconfigurations | Medium |
| 21 | `proc-mount` | `procMount: Unmasked` | High |
| 22 | `unsafe-sysctls` | Unsafe sysctl configuration | High |
| 23 | `runtime-class` | Missing RuntimeClass (when configured) | Low |
| 24 | `share-process-namespace` | `shareProcessNamespace: true` | Medium |
| 25 | `init-container-security` | Init containers not hardened (apply all above checks) | Same as parent |
| 26 | `sidecar-container-security` | K8s 1.28+ native sidecars not hardened | Same as parent |
| 27 | `ephemeral-container-policy` | Ephemeral containers without security restrictions | Medium |

For checks 25-26: these are NOT separate checker implementations. The workload checkers (1-24) must iterate over ALL container types: `containers`, `initContainers`, and sidecar containers (initContainers with `restartPolicy: Always`). Each workload checker handles this as part of its `Run()` method. Check 27 (ephemeral-container-policy) is a separate check.

---

## Coding Standards

### Go Standards

- **Go 1.22+** minimum
- **Module path:** `github.com/stribog-cloud/kubevigil`
- **Formatting:** `gofmt` + `goimports`, enforced by CI
- **Linting:** golangci-lint with config in `.golangci.yml`
- **Error handling:** Always wrap errors with context: `fmt.Errorf("loading config: %w", err)`. Never ignore errors silently.
- **Logging:** Use `log/slog` structured logging. No `fmt.Println` in library code.
- **Naming:** Follow Go conventions — exported types are PascalCase, unexported are camelCase. Check IDs are kebab-case strings. File names are snake_case.
- **Comments:** All exported types, functions, and methods get godoc comments. Non-obvious internal logic gets inline comments.
- **Dependencies:** Minimize. Core deps for Phase 1:
  - `k8s.io/client-go` — Kubernetes API client
  - `k8s.io/apimachinery` — K8s types
  - `github.com/spf13/cobra` — CLI framework
  - `github.com/stretchr/testify` — Test assertions
  - `golang.org/x/sync/errgroup` — Concurrent execution
  - `gopkg.in/yaml.v3` — YAML parsing (config + manifest)
  - `github.com/fatih/color` — Terminal colors (respects NO_COLOR)
- **No additional dependencies** without explicit justification. Standard library preferred.

### Code Organization Rules

- `internal/` is private — no external imports allowed. This is all implementation.
- `pkg/` is public API — do NOT create `pkg/` in Phase 1. Everything is internal until Phase 7.
- Each checker is a single file + single test file. Do not combine multiple checks in one file.
- Each checker package has a `register.go` with an `init()` function that registers all checks in that package with the central registry.
- Test files live next to the code they test (`privileged.go` → `privileged_test.go`).
- Test fixtures are YAML files in `test/fixtures/<check-id>/`. Each check gets its own fixture directory.
- Test helpers are in `test/helpers/` and are importable by all test files.

---

## Testing Rules (Non-Negotiable)

### TDD is mandatory. No exceptions.

Every feature follows Red → Green → Refactor:
1. **Write the test first.** For a checker: create fixture YAML files, write table-driven test. Run it — it must FAIL.
2. **Write minimal implementation** to make the test pass. Run it — it must PASS.
3. **Refactor** with tests protecting you. Add edge cases to the test table. Run — still PASS.

**Never write implementation code before its test exists.**

### Test Types Required for Phase 1

**Unit tests (every checker, every function):**
- Table-driven tests with named subtests for every checker
- Positive cases (should detect the issue)
- Negative cases (should NOT detect — secure resources)
- Edge cases (nil securityContext, empty pod spec, multiple containers)
- All container types tested: regular containers, init containers, sidecar containers
- All workload types tested: Pod, Deployment, StatefulSet, DaemonSet, Job, CronJob

**Contract tests (interface stability):**
- `TestAllCheckersContract` — iterate ALL registered checkers, verify:
  - `Name()` returns non-empty kebab-case string
  - `Description()` returns non-empty string
  - `Categories()` returns at least one valid category
  - `RequiredResources()` returns valid GVRs
  - `Run()` with empty resources returns no findings and no error
  - `Run()` with cancelled context returns error
  - `Run()` findings have all required fields populated (Checker, Message, Remediation, Severity, Resource, Kind)
- `TestAllReportersContract` — verify text and JSON reporters both handle empty findings and populated findings correctly

**Integration tests:**
- Full manifest scan pipeline: load directory of fixtures → scan → verify findings
- Config with exemptions: verify findings are suppressed for exempted resources
- CLI exit codes: verify correct exit code for clean scans and scans with findings

### Test Fixture Rules

- Every check MUST have at least:
  - One failing fixture (insecure resource that triggers the check)
  - One passing fixture (secure resource that does NOT trigger)
  - Fixtures for multiple workload types (at minimum: Pod and Deployment)
- Fixture files are minimal — only include the fields relevant to the check
- Multi-document YAML fixtures (separated by `---`) for testing batched scanning

### Coverage Targets

- Line coverage: ≥ 85%
- Every checker has tests: enforced by contract test (if it's registered, it's tested)
- Every check has fixtures: enforced by CI script

---

## Workflow Rules

### Planning

- Enter plan mode for ANY non-trivial task (3+ steps or architectural decisions)
- If something goes sideways, STOP and re-plan immediately — don't keep pushing
- Write detailed specs upfront to reduce ambiguity
- Before implementing a checker, plan: what fixture YAMLs are needed, what edge cases exist, what K8s resource fields are inspected

### Parallel Execution

**Use subagents when:**
- Implementing independent checkers (each check is self-contained)
- Writing fixture YAML files
- Running tests while implementing the next checker

**Use agent teams when:**
- Building the checker interface + registry + scanner simultaneously
- Implementing CLI + report formatting + engine integration

**Agent team rules:**
- Lead orchestrates — does NOT write code itself
- Each teammate owns distinct files — never two agents editing the same file
- Give teammates specific context: file paths, constraints, definition of done
- Start with read-only tasks (reviews, research) before parallel implementation

### Task Tracking

This project uses **tasks** (`bd`) for issue tracking.

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --status in_progress  # Claim work
bd close <id>         # Complete work
bd sync               # Sync with git
```

- Create tasks issues for each checker, each infrastructure component, each integration test
- Claim work before starting, close after verification
- After ANY correction from the user: file a tasks issue with `lesson` label

### Verification Before Done

- Never mark a task complete without proving it works
- Run `go test ./...` and verify all tests pass
- Run `go vet ./...` and `golangci-lint run`
- For checkers: demonstrate that the failing fixture produces findings AND the passing fixture produces zero findings
- Ask yourself: "Would a staff engineer approve this?"

### Session Completion (Landing the Plane)

When ending a work session, ALL steps are mandatory:
1. File tasks issues for remaining work
2. Run quality gates: `go test ./...`, `go vet ./...`, `golangci-lint run`
3. Update tasks issue status
4. Push to remote — this is MANDATORY:
   ```bash
   git pull --rebase
   bd sync
   git push
   git status  # Must show "up to date with origin"
   ```
5. Provide context for next session

**Work is NOT complete until `git push` succeeds. NEVER stop before pushing.**

### Self-Improvement

- After ANY correction from the user: file a tasks issue with the `lesson` label
- Write rules that prevent the same mistake
- Review lessons at session start

---

## Implementation Order (Recommended)

Phase 1 should be implemented in this sequence. Each step builds on the previous.

### Step 1: Project Scaffold
- `go mod init`, directory structure, Makefile, .golangci.yml, .gitignore
- LICENSE (Apache 2.0), empty README.md, this CLAUDE.md
- Verify: `go build ./...` succeeds (even if main.go is minimal)

### Step 2: Core Types & Interfaces
- `internal/checker/checker.go` — Checker interface, Finding, Severity, Category, ScanMode types
- `internal/checker/registry.go` — Registry with Register(), All(), Get(), EnabledChecks()
- `internal/checker/contract_test.go` — Empty for now, will grow as checkers are added
- `test/helpers/` — Fixture loader, assertion helpers, generator functions
- Verify: `go test ./internal/checker/...` passes

### Step 3: Resource Cache & Manifest Parser
- `internal/engine/resource_cache.go` — ResourceCache with Get/List methods per K8s resource type
- `internal/engine/manifest_parser.go` — Parse YAML files/directories into ResourceCache
- Tests for both — especially multi-document YAML, malformed YAML, empty files
- Verify: Can load a directory of YAML fixtures into a ResourceCache

### Step 4: First Checker (TDD Exemplar)
- `privileged` check — this is the simplest, most clear-cut check
- TDD cycle: fixtures first → test first → implement → refactor
- This establishes the pattern ALL subsequent checkers follow
- Verify: Contract test passes for this checker

### Step 5: Remaining Workload Checkers (Bulk)
- Implement all 24 workload checks following the pattern from Step 4
- Each check: fixtures → test → implement → refactor
- Group related checks (e.g., host-pid + host-ipc + host-network are similar)
- Verify: Contract test passes for ALL checkers

### Step 6: Scan Engine (Orchestrator)
- `internal/engine/scanner.go` — Orchestrates: get enabled checks → collect required resources → populate cache → run checks concurrently → collect findings
- For live mode: uses client-go to fetch resources
- For manifest mode: uses manifest parser
- Tests with fake/mock K8s client
- Verify: Full scan of fixture directory produces expected findings

### Step 7: Reports (Text + JSON)
- `internal/report/reporter.go` — Reporter interface
- `internal/report/text.go` — Colored terminal output with severity indicators
- `internal/report/json.go` — Structured JSON output
- Reporter contract tests
- Golden file tests for deterministic output
- Verify: Both reporters produce valid, readable output

### Step 8: Configuration
- `internal/config/config.go` — Parse `.kubevigil.yaml`
- `internal/config/exemptions.go` — Exemption matching (namespace, resource, annotation)
- Config discovery (cwd → home → XDG → --config flag)
- Tests for valid configs, invalid configs, exemption matching
- Verify: Exempted resources produce zero findings

### Step 9: CLI
- `cmd/kubevigil/` — Cobra commands: root, scan, list, version
- Wire everything together: CLI → config → engine → checkers → report → output
- Exit codes per specification
- Verify: `kubevigil scan --file test/fixtures/` works end-to-end

### Step 10: Integration Tests & Polish
- Full pipeline integration tests
- README with getting started guide
- Example config file
- `make build`, `make test`, `make lint` targets
- Verify: `make test` passes, binary runs, output is professional

---

## Quality Standards

### Code Elegance
- For non-trivial changes: pause and ask "is there a more elegant way?"
- If a fix feels hacky: "Knowing everything I know now, implement the elegant solution"
- Skip this for simple, obvious fixes — don't over-engineer
- Challenge your own work before presenting it

### Simplicity First
- Make every change as simple as possible
- Impact minimal code
- Find root causes — no temporary fixes
- Changes should only touch what's necessary

### Autonomous Bug Fixing
- When given a bug report: just fix it. Don't ask for hand-holding.
- Point at logs, errors, failing tests — then resolve them
- Go fix failing tests without being told how

---

## Key Decisions (Pre-Made)

These decisions are final. Don't re-debate them.

- **CLI framework:** Cobra (not urfave/cli, not raw flag)
- **Test framework:** testify/assert + testify/require (not raw testing only)
- **YAML library:** gopkg.in/yaml.v3 (not v2, not encoding/json for YAML)
- **K8s client:** client-go with fake client for tests (not custom HTTP client)
- **Concurrency:** errgroup (not raw goroutines + WaitGroup)
- **Colors:** fatih/color with NO_COLOR support (not raw ANSI codes)
- **Config format:** YAML (not TOML, not JSON, not HCL)
- **Module path:** `github.com/stribog-cloud/kubevigil`
- **Minimum Go:** 1.22
- **Minimum K8s:** 1.25 (PSA GA, PSP removed)

---

## Reminders

- **Read `docs/kubevigil-features-v2.md` for details** on any check behavior, severity rationale, or architectural decision not covered here. That document is the source of truth for "what" and "why." This CLAUDE.md is the source of truth for "how" and "now."
- **This is a Go learning project.** When multiple approaches exist, choose the one that teaches the best Go patterns (interfaces over concrete types, composition over inheritance, small focused packages, table-driven tests).
- **Init containers and sidecar containers must be checked.** Every workload checker iterates `containers`, `initContainers`, and identifies native sidecars (initContainers with `restartPolicy: Always` on K8s 1.28+). This is a common oversight in real tools — don't repeat it.
- **Severity definitions matter.** Critical = cluster compromise path. High = significant weakness. Medium = defense-in-depth gap. Low = best practice. Info = awareness. Don't inflate severities.
- **The features doc has 112 total checks across 13 categories.** Phase 1 implements 27 (workload + lifecycle). The architecture must cleanly support adding the remaining 85 checks in Phase 2 without refactoring the core.
