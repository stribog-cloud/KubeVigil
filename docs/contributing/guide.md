# Contributing Guide

KubeVigil welcomes contributions. This guide covers the development setup, code standards, and step-by-step instructions for the most common contribution types: adding a new security check and adding a new fix strategy.

## Prerequisites

- **Go 1.22+** ([install](https://go.dev/doc/install))
- **make** (included on macOS and most Linux distributions)
- **golangci-lint** ([install](https://golangci-lint.run/usage/install/)) for linting
- **Bats** ([install](https://bats-core.readthedocs.io/)) for end-to-end tests (optional)
- **Kind** ([install](https://kind.sigs.k8s.io/)) for live cluster e2e tests (optional)

## Clone and Build

```bash
git clone https://github.com/stribog-cloud/kubevigil.git
cd kubevigil
make build
```

The binary is written to `bin/kubevigil`. Verify it works:

```bash
./bin/kubevigil version
./bin/kubevigil list checks
```

## Run Tests

```bash
# Run all tests with race detection
make test

# Run tests with coverage report
make test-cover

# Run linter
make lint

# Run go vet
make vet

# Run all quality gates (vet + lint + test)
make check
```

All three gates -- `vet`, `lint`, and `test` -- must pass before submitting a PR.

## Code Standards

### Formatting

- Run `gofmt` and `goimports` before committing. `make fmt` does both:
  ```bash
  make fmt
  ```
- The linter (`golangci-lint`) enforces additional rules including `gocritic`, `revive`, and `gosimple`.

### Error Handling

Wrap errors with context using `fmt.Errorf`:

```go
cfg, err := config.Load(path)
if err != nil {
    return fmt.Errorf("loading config from %s: %w", path, err)
}
```

### Logging

Use `log/slog` for structured logging. Never use `fmt.Println` for diagnostic output:

```go
slog.Debug("check completed", "check", c.Name(), "findings", len(findings))
slog.Warn("manifest parse error", "file", path, "error", err)
```

### Dependencies

Minimize external dependencies. The standard library is preferred. New dependencies require justification. Current third-party dependencies:

- `gopkg.in/yaml.v3` -- YAML round-trip via Node API
- `github.com/spf13/cobra` -- CLI framework
- `github.com/fatih/color` -- terminal colors
- `k8s.io/client-go` -- Kubernetes client
- `k8s.io/apimachinery` -- Kubernetes types

### Naming

- Avoid stuttered names (`checker.CheckerInterface` is wrong; `checker.Checker` is right).
- Pass large structs by pointer.
- Use named return values only when they improve readability.

## Adding a New Security Check

This is the most common contribution. Follow these steps:

### 1. Create the Checker File

Create a new file in the appropriate category package. Each check lives in one file:

```
internal/checker/<category>/your_check.go
```

For example, to add a check that detects missing liveness probes in the workload category:

```
internal/checker/workload/liveness_probe.go
```

Implement the `Checker` interface:

```go
package workload

import (
    "context"
    "github.com/stribog-cloud/kubevigil/internal/checker"
    // ...
)

// LivenessProbeChecker detects containers without liveness probes.
type LivenessProbeChecker struct{}

func (c *LivenessProbeChecker) Name() string        { return "liveness-probe-missing" }
func (c *LivenessProbeChecker) Description() string  { return "Detects containers without a liveness probe configured." }
func (c *LivenessProbeChecker) Categories() []checker.Category { return []checker.Category{checker.CategoryWorkload} }
func (c *LivenessProbeChecker) SupportedModes() []checker.ScanMode {
    return []checker.ScanMode{checker.ScanModeLive, checker.ScanModeManifest}
}
func (c *LivenessProbeChecker) RequiredResources() []schema.GroupVersionResource {
    return workload.GVRs()
}

func (c *LivenessProbeChecker) Run(ctx context.Context, resources *checker.ResourceCache) ([]checker.Finding, error) {
    // Implementation here
}
```

### 2. Register the Checker

Add the checker to the category's `register.go` file in its `init()` function:

```go
func init() {
    checker.DefaultRegistry().MustRegister(&LivenessProbeChecker{})
}
```

### 3. Write the Test File

Create a test file alongside the checker. Use table-driven tests with at least 15 test cases:

```
internal/checker/workload/liveness_probe_test.go
```

```go
func TestLivenessProbeChecker(t *testing.T) {
    tests := []struct {
        name     string
        fixture  string
        wantLen  int
        wantSev  checker.Severity
    }{
        {name: "deployment with probe", fixture: "passing/deployment.yaml", wantLen: 0},
        {name: "deployment without probe", fixture: "failing/deployment.yaml", wantLen: 1, wantSev: checker.SeverityMedium},
        // ... at least 13 more cases
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Test implementation using fixture loader
        })
    }
}
```

### 4. Add Test Fixtures

Create passing and failing YAML fixtures:

```
test/fixtures/liveness-probe-missing/
  passing/
    deployment.yaml
  failing/
    deployment.yaml
```

Fixtures should be minimal but realistic Kubernetes manifests.

### 5. Add Framework Mappings

If your check maps to a compliance framework control, add the mapping in `internal/frameworks/`. The mapping functions associate check names with CIS, MITRE ATT&CK, and NSA/CISA controls.

### 6. Run Contract Tests

Contract tests in `test/integration/contract_test.go` automatically iterate all registered checkers and verify interface compliance:

```bash
go test ./test/integration/ -run TestCheckerContract
```

Every registered checker must:

- Return a non-empty `Name()`.
- Return a non-empty `Description()`.
- Return at least one category.
- Return at least one supported mode.
- Return at least one required resource.

### 7. Verify Everything Passes

```bash
make check
```

## Adding a Fix Strategy

To make an existing check auto-fixable:

### 1. Add a Registry Entry

Add the strategy to `DefaultRegistry()` in `internal/fix/registry.go`:

```go
r.MustRegister(&Strategy{
    CheckID:      "liveness-probe-missing",
    Safety:       checker.FixPotentiallyBreaking,
    Operation:    checker.FixOpAdd,
    FieldPath:    "spec.containers[*].livenessProbe",
    DesiredValue: map[string]any{
        "httpGet": map[string]any{
            "path": "/healthz",
            "port": 8080,
        },
        "initialDelaySeconds": 15,
        "periodSeconds":       10,
    },
    Description:  "Adds a default liveness probe.",
    Impact:       "Applications without a /healthz endpoint will be restarted by kubelet.",
})
```

### 2. Choose the Correct Safety Classification

| Classification | When to Use | Examples |
|---------------|-------------|----------|
| `checker.FixSafe` | Zero risk of breaking functionality | Setting `privileged: false`, disabling `allowPrivilegeEscalation` |
| `checker.FixLikelySafe` | Very low risk, could theoretically break edge cases | `drop: ["ALL"]` for capabilities, `runAsNonRoot: true` |
| `checker.FixPotentiallyBreaking` | Could break functionality for some workloads | Adding default resource limits, removing host ports |
| `checker.FixManualOnly` | Cannot be automated | Do not register these; they are guidance-only |

### 3. Add FixHint to the Checker

In the checker's `Run` method, populate the `FixHint` field on each finding:

```go
findings = append(findings, checker.Finding{
    // ... standard fields ...
    FixHint: &checker.FixHint{
        Safety:      checker.FixPotentiallyBreaking,
        Description: "Adds a default liveness probe.",
        Impact:      "Applications without a /healthz endpoint will be restarted.",
        Operation:   checker.FixOpAdd,
    },
})
```

### 4. Test Round-Trip YAML Preservation

Verify that the fix preserves YAML comments and formatting. The fix engine uses the `yaml.v3` Node API -- do not marshal/unmarshal for round-trip editing. Run the fix integration tests:

```bash
go test ./test/integration/ -run TestFix
```

### 5. Test the Full Workflow

Run the golden workflow: scan, fix, re-scan, and verify zero findings:

```bash
kubevigil scan -f test/fixtures/fix/your-fixture.yaml -o json
kubevigil fix test/fixtures/fix/your-fixture.yaml --apply --risk-level aggressive
kubevigil scan -f test/fixtures/fix/your-fixture.yaml -o json
```

The re-scan should report zero findings for the check you fixed.

## PR Guidelines

- **One feature per PR.** A new check is one PR. A new fix strategy is one PR. Do not bundle unrelated changes.
- **Tests are required.** Every new check needs a test file with table-driven tests. Every new fix strategy needs round-trip tests.
- **Backward compatibility is non-negotiable.** All existing tests must continue to pass. Do not change the Checker interface, Finding struct, or config format in breaking ways.
- **Follow the existing patterns.** Look at existing checkers in the same category for reference. The codebase is intentionally consistent.
- **Run `make check` before pushing.** This runs vet, lint, and all tests.

## Project Layout Conventions

| Convention | Rule |
|-----------|------|
| One file per component | Each checker, reporter, or fix component is in its own file |
| One test file per component | `foo.go` has `foo_test.go` |
| Fixtures in `test/fixtures/` | Scan fixtures in `test/fixtures/<check-id>/`, fix fixtures in `test/fixtures/fix/` |
| Table-driven tests | 15+ cases per checker test |
| Contract tests | `test/integration/contract_test.go` verifies all registered checkers |

## See Also

- [Architecture Overview](../architecture/overview.md) -- internal design and data flow
- [Checks Overview](../checks/overview.md) -- all 110 checks at a glance
- [Fix Overview](../auto-fix/overview.md) -- how auto-fix works
- [Configuration File](../configuration/config-file.md) -- `.kubevigil.yaml` reference
