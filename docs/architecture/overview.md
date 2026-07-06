# Architecture Overview

This page describes KubeVigil's internal architecture for contributors and advanced users. It covers the project structure, key abstractions, data flow through the scan and fix pipelines, and the design decisions behind them.

## Project Structure

```
cmd/kubevigil/              CLI entrypoint (Cobra commands)
internal/
  checker/                  Core types, Checker interface, Registry, ResourceCache
    cloud/                  Cloud provider checks
    cluster/                Cluster configuration checks
    crd/                    Custom resource checks
    image/                  Image security checks
    network/                Network security checks
    psa/                    Pod Security Standards checks
    rbac/                   RBAC checks
    scheduling/             Scheduling checks
    secrets/                Secrets management checks
    storage/                Storage checks
    supply_chain/           Supply chain checks
    workload/               Workload security checks (largest category)
  config/                   Configuration loading, validation, exemptions
  engine/                   Scan orchestration, manifest parsing
  fix/                      Auto-remediation engine
  frameworks/               Compliance framework mappings (CIS, MITRE, NSA)
  k8s/                      Kubernetes client construction
  report/                   Output formatters (8 formats)
  version/                  Build version metadata
test/
  fixtures/                 YAML fixtures for scan tests
    fix/                    YAML fixtures for fix tests
  helpers/                  Test generators, assertions, fixture loaders
  integration/              Contract tests, fix pipeline tests
  e2e/                      Bats end-to-end tests
```

## Core Abstractions

### Checker Interface

Every security check implements the `Checker` interface defined in `internal/checker/checker.go`:

```go
type Checker interface {
    Name() string
    Description() string
    Categories() []Category
    SupportedModes() []ScanMode
    RequiredResources() []schema.GroupVersionResource
    Run(ctx context.Context, resources *ResourceCache) ([]Finding, error)
}
```

- **Name** returns a kebab-case identifier (e.g., `privileged`, `run-as-root`).
- **Categories** classifies the check (Workload, RBAC, Network, etc.). A check can belong to multiple categories.
- **SupportedModes** declares whether the check works in live mode, manifest mode, or both.
- **RequiredResources** lists the Kubernetes GVRs the check needs (e.g., `apps/v1/deployments`). The engine uses this to pre-fetch only the resources each check needs.
- **Run** executes the check against a `ResourceCache` and returns zero or more `Finding` values.

### Registry

The `checker.Registry` holds all registered checkers. Each category package (e.g., `internal/checker/workload/`) has a `register.go` file with an `init()` function that registers its checkers:

```go
func init() {
    checker.DefaultRegistry().MustRegister(&PrivilegedChecker{})
    checker.DefaultRegistry().MustRegister(&PrivilegeEscalationChecker{})
    // ...
}
```

The CLI imports all category packages via blank imports in `cmd/kubevigil/scan.go`, which triggers registration at startup. The registry is immutable after init -- no dynamic loading.

### ResourceCache

`ResourceCache` is a read-only in-memory cache of Kubernetes resources. The engine populates it from either the Kubernetes API (live mode) or parsed YAML files (manifest mode), then passes it to each checker's `Run` method. Checkers never call the Kubernetes API directly.

### Finding

A `Finding` represents a single security issue:

```go
type Finding struct {
    Checker      string
    Severity     Severity
    Resource     string
    Namespace    string
    Kind         string
    Container    string
    Message      string
    Remediation  string
    FieldPath    string
    Frameworks   []FrameworkRef
    CurrentValue any
    DesiredValue any
    FixHint      *FixHint
}
```

The `FixHint` field (added in Phase 3) carries structured metadata for auto-remediation: safety classification, description, operation type, and impact.

## Scan Pipeline

The scan pipeline flows through four stages:

```
Discover Resources --> Run Checks --> Post-Process --> Render Report
```

### 1. Discover Resources

- **Manifest mode** (`-f`): `engine.ParsePath()` walks the file or directory, parses YAML documents, and builds a `ResourceCache`.
- **Live mode**: `k8s.NewClient()` creates dynamic and discovery clients. The engine queries the API for all resource types required by enabled checks.

### 2. Run Checks

`Scanner.runChecks()` runs enabled checks concurrently using `errgroup` with configurable concurrency (`settings.concurrency`). Each check receives the shared `ResourceCache` and returns findings independently. Checks that error out are counted but do not abort the scan.

### 3. Post-Process

After all checks complete, the engine:

1. Applies severity overrides from the config file.
2. Filters findings against exemptions (resource name, namespace, check ID, annotations).
3. Attaches compliance framework references via `frameworks.AttachFrameworks()`.

The CLI then applies additional filters: severity threshold, namespace inclusion/exclusion, infrastructure namespace exclusion, and framework filtering.

### 4. Render Report

The `report` package provides 8 format implementations, each registered via `init()`:

| Format | File | Description |
|--------|------|-------------|
| `text` | `text.go` | Human-readable terminal output with color |
| `json` | `json.go` | Machine-readable JSON |
| `yaml` | `yaml.go` | Machine-readable YAML |
| `markdown` | `markdown.go` | Markdown tables for PR comments |
| `html` | `html.go` | Interactive HTML dashboard |
| `sarif` | `sarif.go` | SARIF v2.1.0 for GitHub Code Scanning |
| `junit` | `junit.go` | JUnit XML for CI/CD |
| `csv` | `csv.go` | CSV for spreadsheet import |

All reporters implement the `Reporter` interface:

```go
type Reporter interface {
    Name() string
    Generate(ctx context.Context, result *checker.ScanResult, w io.Writer) error
}
```

The CLI resolves the output target (stdout or file) based on the `-o` flag. File extensions are mapped to formats automatically (e.g., `report.html` infers `html` format).

## Fix Pipeline

The fix engine in `internal/fix/` follows a seven-stage pipeline:

```
Scan --> Filter --> Classify --> Gate --> Plan --> Backup --> Patch --> Verify
```

### 1. Scan

The fixer reuses the scan engine to discover findings in the target manifests. Only findings with a registered fix strategy are candidates.

### 2. Filter

Findings are filtered by CLI flags: `--checks`, `--severity`, `--namespace`, `--exclude-namespace`, `--fingerprint`.

### 3. Classify

Each finding is matched against the fix registry (`internal/fix/registry.go`) to determine:

- **Safety level**: Safe, Likely Safe, Potentially Breaking, or Manual Only.
- **Operation**: Set, Add, Remove, or Merge.
- **Field path**: The YAML path to modify (e.g., `spec.containers[*].securityContext.privileged`).
- **Desired value**: The secure value to set.

### 4. Gate

The safety classifier applies three gates:

1. **Risk level gate**: Fixes above the requested `--risk-level` are skipped.
2. **System namespace gate**: Resources in system namespaces are blocked unless `--i-understand-system-namespaces` is set.
3. **Known workload gate**: Recognized infrastructure workloads (CNI plugins, storage drivers, monitoring exporters) are flagged with impact warnings.

### 5. Plan and Backup

The fixer builds a `Plan` with all approved fixes, generates unified diffs, and (when `--apply` is set) creates a backup directory with copies of original files and a `RESTORE.md` guide.

### 6. Patch

`yaml_patcher.go` applies fixes using the `yaml.v3` Node API for round-trip fidelity. This preserves:

- Comments (inline and block)
- Key ordering
- Indentation style
- Quoting style
- Blank lines

The patcher navigates the YAML node tree to the target field path, then sets, adds, removes, or merges the value. It never marshals/unmarshals the full document -- it modifies nodes in place.

### 7. Verify

When `--verify` is set, the fixer re-scans the patched files and compares findings to the pre-fix state. It reports how many findings were resolved, how many remain, and whether any new findings were introduced.

## Compliance Framework Mappings

The `internal/frameworks/` package maps check IDs to controls in three frameworks:

- **CIS Kubernetes Benchmark v1.8**: Section/control numbering (e.g., `5.2.1`).
- **MITRE ATT&CK for Containers v14**: Technique IDs (e.g., `T1611`).
- **NSA/CISA Kubernetes Hardening Guide v1.2**: Section references.

`frameworks.AttachFrameworks()` is called during post-processing to add `FrameworkRef` entries to each finding. `frameworks.FilterByFramework()` supports the `--framework` CLI flag.

## Key Design Decisions

### No Live Cluster Patching

The fix command generates artifacts (patched YAML, kubectl commands, Kustomize overlays, Helm values). It never executes commands against the Kubernetes API. This eliminates the risk of accidentally modifying a running cluster.

### Dry-Run by Default

Running `kubevigil fix ./manifests/` without `--apply` shows diffs but modifies nothing. This makes it safe to run in any environment, including production CI pipelines, without risk.

### Mandatory Backup

Every `--apply` operation creates a timestamped backup directory with original file copies and a `RESTORE.md` file. There is no `--no-backup` flag. Recovery is always one copy command away.

### System Namespace Protection

Resources in `kube-system`, `kube-public`, and `kube-node-lease` are never auto-fixed. The opt-in flag `--i-understand-system-namespaces` is intentionally long to prevent accidental use. Additional system namespaces can be configured in `.kubevigil.yaml`.

### YAML Round-Trip Fidelity

The fix engine uses the `yaml.v3` Node API exclusively. It never deserializes YAML into Go structs for round-trip editing. This preserves every comment, blank line, and formatting choice in the original file. The patched output is byte-identical to the original except for the specific fields being fixed.

### Additive Risk Levels

Risk levels are cumulative:

- `safe`: Safe fixes only.
- `moderate`: Safe + Likely Safe.
- `aggressive`: Safe + Likely Safe + Potentially Breaking.

Manual-only fixes are never auto-applied regardless of risk level.

### Checker Independence

Each checker is self-contained in a single file with a corresponding test file. Checkers share no mutable state -- the `ResourceCache` is read-only, and findings are returned as values. This makes checks safe to run concurrently and easy to test in isolation.

## See Also

- [Contributing Guide](../contributing/guide.md) -- how to add checks and fix strategies
- [Checks Overview](../checks/overview.md) -- all 150 checks at a glance
- [Fix Overview](../auto-fix/overview.md) -- user-facing fix documentation
- [Configuration File](../configuration/config-file.md) -- `.kubevigil.yaml` reference
