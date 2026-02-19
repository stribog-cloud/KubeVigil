# KubeVigil Testing Strategy

KubeVigil is a Kubernetes Security Posture Management (KSPM) CLI tool that scans clusters and manifests for security misconfigurations. This document describes the testing strategy adopted for the project — the reasoning behind it, how each layer works, and how they fit together to provide confidence across 110 security checkers, multiple report formats, and diverse cluster topologies.

## Guiding Principles

The strategy is rooted in a few core beliefs shaped by the nature of the project:

1. **The Testing Pyramid applies, even to CLI tools.** Heavy unit tests, moderate integration tests, lean end-to-end tests. The pyramid optimises for speed and cost-efficiency — unit tests run in milliseconds, E2E tests against live clusters take minutes.
2. **Contract testing is the structural backbone.** With 110 checkers registered via `init()` functions across 12 packages, a formal interface contract prevents regressions at scale without requiring exhaustive per-checker integration tests.
3. **Shift-left everything.** Static analysis, race detection, linting, and coverage tracking run on every commit. Problems caught in CI are orders of magnitude cheaper than problems caught in production scans.
4. **Test infrastructure is a first-class investment.** Fixture loaders, test helpers, golden files, and Kind cluster configurations are not afterthoughts — they are foundational code that makes writing new tests trivial as the checker count grows.
5. **Maximise what can be tested without a cluster.** KubeVigil's manifest-mode scanning means the vast majority of checker logic can be exercised against YAML fixtures without ever touching a Kubernetes API server.

6. **TDD is the development methodology, not an afterthought.** Tests are written before the implementation they verify. This applies to core domain logic, test infrastructure, and even E2E shell scripts. The red-green-refactor cycle is how KubeVigil code gets written.

---

## Test-Driven Development — How Code Gets Written

KubeVigil follows Test-Driven Development (TDD) as its primary development methodology. This is not a retrofitted practice — TDD has been the approach since the very first commit, and it shapes how every piece of the codebase is built.

### Why TDD for a Security Scanner

TDD forces clean architecture from day one. For a security scanner, this is especially valuable:

- **Checkers are pure functions.** A checker takes a `ResourceCache` and returns `[]Finding`. This is the ideal shape for TDD — the input and output are well-defined, making it natural to write the expected findings first, then implement the detection logic to produce them.
- **Interfaces are defined by tests, not by implementation.** The `Checker` interface, `ResourceCache`, `Registry`, and `ScanResult` types were all shaped by writing tests that consumed them before writing the code that implemented them. This produced cleaner APIs than a design-first approach would have.
- **Regressions are caught immediately.** When a checker is modified (say, to reduce false positives), the existing tests for that checker act as a safety net. TDD ensures those tests exist from the moment the checker does.

### The TDD Cycle in Practice

The development of each component followed the red-green-refactor pattern:

**Phase 1 — Core Types and Interfaces**

The foundational types (`Checker`, `Finding`, `Severity`, `ResourceCache`, `Registry`) were built test-first. The `registry_test.go` file — with table-driven tests for `Register`, `MustRegister`, `Get`, `All`, `Names`, and `Len` — was written before `registry.go` existed. The test helpers themselves (`generators.go`, `fixture_loader.go`, `assertions.go`) were also developed with their own TDD tests (`generators_test.go`, `fixture_loader_test.go`) before being used in checker tests, ensuring the test infrastructure was reliable before depending on it.

**Phase 1 — Workload Checkers**

Each of the 24 workload checkers followed the same cycle: write a test that loads a fixture, runs the checker, and asserts specific findings → watch it fail (red) → implement the checker logic → watch it pass (green) → refactor for clarity and performance. The fixture YAML files were created as part of the "red" step, representing the Kubernetes misconfiguration the checker should detect.

**Phase 2 — All Remaining Checker Categories**

The pattern scaled cleanly to the 85 Phase 2 checkers across image, RBAC, secrets, network, PSA, scheduling, storage, cluster configuration, supply chain, cloud, and CRD categories. The contract test (`contract.go`) was itself written test-first — the test defined what properties every checker must have, then the `RunCheckerContractTests` function was implemented to enforce them.

**E2E Shell Scripts — Tests Before Scripts**

TDD extended beyond Go code to the E2E infrastructure. The Bats test files in `test/e2e/scripts/tests/` were written *before* the shell scripts they test. The `test_helper.bash` defined mocks for `kind`, `kubectl`, and `kubevigil`, along with assertion helpers, before any orchestration script existed. The scripts in `test/e2e/scripts/` were then implemented to make the Bats tests pass — the same red-green-refactor cycle, applied to shell scripting.

### What TDD Produces

The discipline of writing tests first had concrete architectural consequences:

- **The `ResourceCache` API is consumer-driven.** Its methods (`Add`, `List`, `ListNamespaced`, `GVRs`, `Len`) exist because checker tests needed them, not because an upfront design document specified them.
- **The fixture system emerged from necessity.** Loading YAML into a `ResourceCache` for testing was a repeated pattern in early checker tests, which drove the creation of the `test/helpers/fixture_loader.go` utilities.
- **The contract test is a living specification.** Because the contract was written as a test before any checker existed, it defined the rules of the game upfront. New checkers are written to satisfy the contract, not the other way around.
- **Test data generators use the functional options pattern.** `GeneratePod(WithHostPID(), WithPrivileged(), WithCapabilities("NET_ADMIN"))` reads as a specification of the resource being created. This pattern was driven by the desire to write expressive tests first.

### TDD vs. BDD

KubeVigil uses TDD throughout because the primary "users" of the codebase are developers adding new checkers. The fixture YAML files serve a BDD-like role — they are readable specifications of "given this Kubernetes configuration, the scanner should find these issues" — but the test code itself is standard Go `testing` package code rather than Gherkin-style specs. This keeps the toolchain simple and avoids an additional DSL layer.

---

## Layer 1: Unit Tests — The Foundation

Unit tests constitute roughly 70% of the test suite by volume. They live alongside the source code as `*_test.go` files within each package and test individual functions, methods, and behaviours in isolation.

### What Gets Unit Tested

Every core package has dedicated unit tests:

- **`internal/checker/`** — Registry operations (registration, lookup, listing), resource cache behaviour (add, retrieve, GVR resolution), and type-level invariants.
- **`internal/report/`** — Each of the eight report formats (Text, JSON, Markdown, HTML, SARIF, CSV, JUnit, YAML) has its own test file verifying output structure, field correctness, and edge cases like empty findings or missing metadata. The HTML remediation rendering has a separate dedicated test.
- **`internal/config/`** — Configuration parsing, exemption matching logic, and namespace filtering rules.
- **`internal/engine/`** — The manifest parser (multi-document YAML handling, malformed input, empty documents) and the scanner orchestration logic.
- **`internal/frameworks/`** — CIS, MITRE ATT&CK, and NSA framework mapping correctness.
- **`internal/k8s/`** — Kubernetes client construction and resource filtering logic.
- **`internal/version/`** — Version string formatting and build metadata.
- **`cmd/kubevigil/`** — CLI argument parsing, output format selection, and command wiring.

### Fixture-Based Testing

The centrepiece of the unit testing strategy is the **fixture system**. The `test/fixtures/` directory contains over 100 subdirectories — one per security check ID — each holding YAML manifests that represent specific Kubernetes misconfigurations.

```
test/fixtures/
├── privileged/              # Pods running in privileged mode
├── run-as-root/             # Containers running as root
├── rbac-cluster-admin/      # Overly broad RBAC bindings
├── network-policy-missing/  # Namespaces without NetworkPolicies
├── secrets-in-env/          # Secrets exposed via environment variables
└── ... (100+ directories)
```

The `test/helpers/fixture_loader.go` package provides utilities that parse these YAML files into a `ResourceCache` — the same in-memory structure that the scan engine populates from a live cluster or manifest directory:

- **`LoadFixture(t, checkID, filename)`** — Loads a single YAML file (handling multi-document `---` separators) into a cache.
- **`LoadFixtureDir(t, checkID)`** — Loads all YAML files from a check's fixture directory.
- **`LoadFixtureRaw(t, checkID, filename)`** — Returns raw bytes for tests that need to inspect unparsed content.

This design means individual checker tests can run against realistic Kubernetes resources without requiring a live cluster, a kind installation, or even network access. A typical checker unit test looks like: load fixtures, run the checker against the cache, assert the expected findings appear with the correct severity, resource, and message.

### Test Helpers and Generators

The `test/helpers/` package also provides:

- **`assertions.go`** — Custom assertion helpers tailored to KubeVigil's domain (finding count assertions, severity distribution checks, check ID presence verification).
- **`generators.go`** — Test data generators that produce valid `Finding`, `ScanResult`, and `ResourceCache` instances with sensible defaults, reducing boilerplate in test code.

---

## Layer 2: Contract Testing — The Structural Guarantee

With 110 checkers spread across 12 packages (`workload`, `image`, `rbac`, `secrets`, `network`, `psa`, `scheduling`, `storage`, `cluster`, `supply_chain`, `cloud`, `crd`), individually integration-testing every checker against every edge case is not practical. Instead, KubeVigil enforces a **formal interface contract** that every checker must satisfy.

### The Contract

Defined in `internal/checker/contract.go`, the contract specifies:

| Property | Requirement |
|---|---|
| `Name()` | Non-empty, kebab-case string matching `^[a-z][a-z0-9]*(-[a-z0-9]+)*$` |
| `Description()` | Non-empty string |
| `Categories()` | At least one valid category |
| `SupportedModes()` | At least one valid scan mode |
| `RequiredResources()` | At least one GVR with non-empty Resource and Version fields |
| `Run()` with empty cache | Returns zero findings and no error |
| `Run()` with cancelled context | Returns an error |

The last two properties are particularly important. The empty-cache test ensures checkers handle missing data gracefully — a real scenario when scanning a manifest that doesn't contain the resource types a checker inspects. The cancelled-context test ensures checkers respect context cancellation, which matters for scan timeouts and user interrupts.

### Where It Runs

The contract is enforced at two levels:

1. **Package-level** (`internal/checker/contract_test.go`) — Runs against whatever checkers are registered in the `checker` package's test binary. This catches issues during development of the checker framework itself.
2. **Integration-level** (`test/integration/contract_test.go`) — Imports all 12 checker packages to trigger their `init()` registration, then runs the contract against all 110 checkers. This is the authoritative test that verifies the entire checker catalogue.

The integration contract test also includes an explicit registration verification that lists every expected checker ID and asserts the registry contains exactly 110 entries. This prevents silent checker loss — if a package's `init()` function breaks or a checker is accidentally removed, CI fails immediately.

### Why This Matters

This is KubeVigil's equivalent of consumer-driven contract testing in a microservices architecture. The `Checker` interface is the contract, each checker package is a "producer," and the scan engine is the "consumer." The contract test suite guarantees that any checker can be loaded, queried for metadata, and executed without the engine needing to know anything about its internals. This decoupling is what makes it practical to maintain 110 checkers across 12 packages without combinatorial test explosion.

---

## Layer 3: Integration Tests — Cross-Package Verification

Integration tests live in `test/integration/` and exercise the interaction between multiple packages — particularly the flow from configuration through scan engine to findings.

### Full Pipeline Tests

`scan_manifest_test.go` wires up the real `Scanner`, `Registry`, and `Config`, then runs the complete scan pipeline against fixture directories. These tests verify:

- The scanner correctly discovers and parses YAML files from a directory.
- Checkers are selected and executed based on the scan mode and resource availability.
- Findings are aggregated correctly with the right checker attribution.
- Scan metadata (checks run, duration, scan mode) is populated accurately.

A representative test creates an inline YAML manifest with multiple security issues (privileged container, running as root, no resource limits, host networking) and asserts that the scan produces findings from multiple different checkers — verifying that the engine fans out correctly across the checker registry.

### Configuration Integration

`config_exemptions_test.go` tests that exemption rules in the configuration actually suppress findings during a real scan — verifying that the config package and the scan engine interact correctly, not just that each works in isolation.

### Phase 2 Coverage

`scan_phase2_test.go` extends the pipeline tests to cover Phase 2 checkers (image, RBAC, secrets, network, PSA, scheduling, storage, cluster configuration, supply chain, cloud, CRD), ensuring that the later-developed checkers integrate correctly with the same engine that was built for Phase 1 workload checkers.

---

## Layer 4: Golden File Tests — Output Stability

KubeVigil produces reports in eight formats that downstream tools and scripts may parse. Unintended changes to report structure — even whitespace differences — can break consumers. Golden file tests guard against this.

### How It Works

The `internal/report/golden_test.go` file:

1. Constructs a deterministic `ScanResult` from a fixed `goldenScanResult()` function (hardcoded findings, cluster info, and scan metadata with a pinned timestamp).
2. Generates a report using each reporter implementation.
3. Compares the output byte-for-byte against reference files in `test/golden/`.

```
test/golden/
├── text-report.txt
├── json-report.json
├── markdown-report.md
├── html-report.html
├── sarif-report.json
├── csv-report.csv
├── junit-report.xml
└── yaml-report.yaml
```

If the output differs, the test fails. If a format change is intentional (adding a new field, adjusting layout), the developer runs `UPDATE_GOLDEN=1 go test ./internal/report/` to regenerate the golden files and commits the diff for review.

### Why Golden Files Instead of Structural Assertions

Structural assertions (checking that JSON has certain keys, that HTML contains certain elements) would miss subtle regressions like field reordering, whitespace changes, or encoding differences that affect real-world parsers. Byte-for-byte comparison is strict by design — it treats every format as a contract with consumers.

---

## Layer 5: End-to-End Tests — Real-World Validation

The E2E test suite in `test/e2e/` validates KubeVigil's behaviour against realistic scenarios, operating in two modes.

### Manifest Mode (No Cluster Required)

The fastest E2E path scans YAML files directly using `kubevigil scan --file`. Ten scenario directories cover distinct security domains:

| Scenario | Coverage |
|---|---|
| `workload-security/` | 24 workload checks — privileged, capabilities, host namespaces, resource limits |
| `image-security/` | Image tags, digests, registries, pull policy |
| `rbac/` | Wildcard permissions, escalation verbs, cluster-admin, service account config |
| `network/` | NetworkPolicy, Ingress TLS, Service types, external IPs |
| `secrets/` | Secrets in env vars, ConfigMaps, hardcoded manifests |
| `psa/` | Pod Security Admission labels and profile violations |
| `scheduling/` | Tolerations, PriorityClass, PDB, topology, HPA |
| `storage/` | emptyDir, projected volumes, PVC encryption |
| `cluster-hardening/` | Default namespace, quotas, LimitRange, deprecated APIs |
| `mixed/` | Multi-category real-world scenarios |
| `clean/` | Fully hardened deployment — zero-finding negative control |

The `clean/` scenario is important: it contains a fully hardened deployment with every security field explicitly set to the secure value, and asserts that the scanner produces zero findings against it. This serves as a negative control that catches false-positive regressions.

### Live Mode (Kind Clusters)

For checks that inspect cluster state rather than individual manifests — namespace-level checks like `network-policy-missing`, `limit-range-missing`, and `resource-quota-missing` — live mode deploys scenarios to real Kind clusters and runs scans against them.

Three cluster configurations provide progressive complexity:

| Configuration | Topology | Use Case |
|---|---|---|
| `kind-single-node.yaml` | 1 control plane | Fast smoke tests |
| `kind-multi-node.yaml` | 1 CP + 3 workers | Scheduling, topology spread, NetworkPolicy, node affinity |
| `kind-ha-control-plane.yaml` | 3 CP + 2 workers | HA checks, etcd, API server config, component versions |

### Cross-Validation Against Other Scanners

The E2E suite supports cross-validating KubeVigil findings against Trivy, Kubescape, and Polaris by scanning the same manifests with multiple tools and comparing finding counts. This identifies both false positives (findings other tools don't report) and false negatives (findings KubeVigil misses), serving as an external benchmark for detection completeness.

### Shell Infrastructure (Bats)

The `test/e2e/scripts/` directory contains Bats tests that validate the E2E helper library itself — mock creation and cleanup, assertion helpers, prerequisite checking, cluster lifecycle management, and namespace operations. This is testing the test infrastructure, ensuring the E2E framework is reliable before trusting its results.

---

## Shift-Left: Static Analysis and CI

### Linting and Static Analysis

The `.golangci.yml` configuration enables 10 linters that run on every `make lint` invocation:

- **errcheck** — Unchecked error returns
- **govet** — Suspicious constructs the compiler doesn't catch
- **staticcheck** — Advanced static analysis (SA, S, ST categories)
- **unused** — Unused code detection
- **gosimple** — Simplification suggestions
- **gocritic** — Diagnostic, style, and performance checks
- **gofmt / goimports** — Formatting consistency with local import grouping
- **misspell** — Typo detection in comments and strings
- **revive** — Configurable linter enforcing exported names, blank imports, context-as-argument, error return conventions, and more

Test files get relaxed rules (gocritic, revive, and errcheck are excluded) — a pragmatic choice that keeps test code focused on correctness rather than style compliance.

### The Quality Gate

The `make check` target enforces a strict gate:

```
vet → lint → test → "All quality gates passed."
```

All three must pass. This is the developer's local equivalent of the CI pipeline.

### CI Pipeline

The GitHub Actions workflow (`.github/workflows/ci.yml`) runs on every push to `master` and every pull request:

1. **Checkout** and **Go 1.25 setup**
2. **`go test -race -count=1 -coverprofile=coverage.out ./...`** — Runs all tests with race detection enabled and caching disabled (`-count=1`), generating a coverage profile.
3. **Coverage extraction** — Parses the coverage percentage from the profile.
4. **Badge update** — On master pushes, updates a dynamic coverage badge via the Schneegans badges action, providing continuous visibility into test coverage.

The `-race` flag is significant: it instruments the binary with the Go race detector, catching data races that would otherwise manifest as intermittent failures or subtle corruption in concurrent code paths — particularly relevant for the scan engine which fans out across multiple checkers.

---

## How It All Fits Together

The testing layers form a coherent pipeline from inner development loop through CI to release confidence:

```
Developer adds/modifies a checker
        │
        ▼
   Unit Tests (milliseconds)
   • Checker logic against fixtures
   • Contract compliance (name, description, categories, modes, GVRs)
   • Empty-cache and cancelled-context behaviour
        │
        ▼
   Integration Tests (seconds)
   • Full scan pipeline: YAML → parse → check → findings
   • All 110 checkers registered and contract-compliant
   • Config exemptions suppress findings correctly
        │
        ▼
   Golden File Tests (seconds)
   • All 8 report formats produce stable, deterministic output
   • Byte-for-byte comparison catches unintended format drift
        │
        ▼
   make check (local gate)
   • go vet → golangci-lint → all tests
        │
        ▼
   CI Pipeline (minutes)
   • Race detection, coverage tracking, badge update
        │
        ▼
   E2E Tests (minutes)
   • Manifest-mode: 10+ scenarios covering all checker categories
   • Live-mode: Kind clusters (single, multi-node, HA)
   • Negative control: clean scenario = zero findings
   • Cross-validation: compare against Trivy, Kubescape, Polaris
```

Each layer catches a different class of defect:

| Layer | Catches |
|---|---|
| Unit tests | Logic errors in individual checkers, parsers, formatters |
| Contract tests | Interface violations, registration failures, metadata issues |
| Integration tests | Wiring problems between packages, pipeline orchestration bugs |
| Golden file tests | Unintended report format changes that break consumers |
| Static analysis | Code quality issues, unused code, typos, formatting drift |
| E2E (manifest) | Full-pipeline regressions across all security domains |
| E2E (live) | Cluster-state checks that cannot be tested from manifests alone |
| Cross-validation | False positives and false negatives relative to industry tools |

---

## Adding Tests for New Checkers

When a new security checker is added to KubeVigil, the testing strategy requires:

1. **Fixtures** — Create a directory `test/fixtures/<check-id>/` with YAML manifests that trigger the check. Include both positive cases (misconfiguration present) and negative cases (secure configuration).
2. **Unit tests** — Write tests in the checker's package that load fixtures via `helpers.LoadFixture()`, run the checker, and assert findings.
3. **Contract compliance** — The checker automatically gets contract-tested via the integration suite. Add the check ID to the expected list in `test/integration/contract_test.go`.
4. **E2E scenario** — Add manifests to the appropriate `test/e2e/scenarios/<category>/` directory and document expected findings in `test/e2e/expected/README.md`.
5. **Golden file update** — If the checker affects default scan output, update golden files with `UPDATE_GOLDEN=1`.

This checklist ensures every new checker is tested at all five layers from day one, preventing the gradual erosion of test coverage that plagues projects where testing is treated as optional.

---

## Known Gaps and Future Directions

The current strategy is comprehensive for a CLI security scanner, but two areas remain opportunities:

- **Performance benchmarking** — Establishing baseline scan times for fixture suites and tracking regressions. Tools like Go's built-in `testing.B` benchmarks or k6 (for any future API mode) could formalise this. As the checker count grows beyond 110, scan duration becomes a user experience concern.
- **Chaos engineering** — While less applicable to a CLI tool than a long-running service, testing KubeVigil's behaviour against degraded cluster connectivity (partial API server failures, timeout scenarios) would strengthen the resilience of live-mode scanning.

Both are natural extensions of the existing foundation rather than architectural changes — the test infrastructure, fixture system, and CI pipeline are already in place to support them.
