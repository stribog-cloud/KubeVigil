# KubeVigil E2E Test Suite

End-to-end tests that validate KubeVigil's security checks against real
Kubernetes manifests and live clusters. These tests complement the unit tests
and contract tests in the main codebase by exercising the full scan pipeline:
YAML parsing, check execution, finding aggregation, and report output.

---

## Directory Structure

```
test/e2e/
|-- README.md                       # This file
|-- E2E-TEST-REPORT.md              # Full validation report with results
|-- clusters/                       # Kind cluster configurations
|   |-- kind-single-node.yaml       # 1 node — fast smoke tests
|   |-- kind-multi-node.yaml        # 4 nodes — scheduling, topology, NetworkPolicy
|   +-- kind-ha-control-plane.yaml  # 3 CP + 2 workers — HA and etcd checks
|-- scenarios/                      # Scenario directories, each with YAML manifests
|   |-- workload-security/          # 24 workload checks (privileged, caps, host-*, etc.)
|   |-- image-security/             # Image tag, digest, registry, pull policy
|   |-- rbac/                       # RBAC wildcard, escalation, cluster-admin, SA config
|   |-- network/                    # NetworkPolicy, Ingress, Service type, externalIPs
|   |-- secrets/                    # Secrets in env vars, configmaps
|   |-- psa/                        # Pod Security Admission labels and profile violations
|   |-- scheduling/                 # Tolerations, PriorityClass, PDB, topology, HPA
|   |-- storage/                    # emptyDir, projected volumes, PVC encryption
|   |-- cluster-hardening/          # Default namespace, quotas, LimitRange, deprecated APIs
|   |-- mixed/                      # Multi-category real-world scenarios
|   |-- clean/                      # Fully hardened deployment — zero-finding negative control
|   |-- fix-safe/                   # Safe-level fix scenarios (privileged, escalation)
|   |-- fix-moderate/               # Likely-safe fix scenarios (runAsNonRoot, readOnlyRootfs)
|   |-- fix-aggressive/             # Potentially-breaking fix scenarios (resource limits)
|   |-- fix-system-ns/              # System namespace protection (kube-system resources)
|   |-- fix-known-workloads/        # Known system workloads (Calico, CoreDNS, node-exporter)
|   |-- fix-multi-doc/              # Multi-document YAML fix tests
|   |-- fix-comments/               # YAML comment preservation tests
|   |-- fix-clean/                  # Fully hardened (nothing to fix, exit code 4)
|   +-- fix-partial-failure/        # Partial failure resilience (malformed + readonly)
|-- expected/                       # Documentation of expected findings per scenario
|   +-- README.md                   # Check-by-check expected findings reference
|-- scan-results/                   # Scan output (gitignored, created at runtime)
|-- scripts/                        # Automation scripts and Bats tests
|   |-- helpers.sh                  # Shared functions: logging, Kind management, namespaces
|   |-- setup-clusters.sh           # Create Kind clusters (single, multi, HA)
|   |-- deploy-scenarios.sh         # Deploy scenario manifests to cluster
|   |-- run-scan.sh                 # Run KubeVigil scans in multiple formats
|   |-- run-fix.sh                  # Run fix E2E tests (manifest mode)
|   |-- run-fix-live.sh             # Run fix E2E tests (live Kind cluster)
|   |-- teardown-clusters.sh        # Destroy Kind clusters
|   |-- cross-validate.sh           # Run third-party tools for comparison
|   |-- full-suite.sh               # End-to-end orchestrator (setup → scan → teardown)
|   |-- validate-findings.py        # Python script to validate findings per category
|   +-- tests/                      # Bats test files
|       |-- test_helper.bash        # Bats setup/teardown, mocks, assertion helpers
|       |-- helpers.bats            # Tests for helpers.sh (15 tests)
|       |-- setup-clusters.bats     # Tests for setup-clusters.sh (10 tests)
|       |-- deploy-scenarios.bats   # Tests for deploy-scenarios.sh (12 tests)
|       |-- run-scan.bats           # Tests for run-scan.sh (10 tests)
|       |-- teardown-clusters.bats  # Tests for teardown-clusters.sh (8 tests)
|       |-- full-suite.bats         # Tests for full-suite.sh (10 tests)
|       +-- cross-validate.bats     # Tests for cross-validate.sh (10 tests)
+-- third-party/                    # Instructions for scanning third-party projects
    +-- README.md                   # Kubernetes Goat, Online Boutique, Helm charts
```

---

## Prerequisites

### Required

| Tool | Version | Purpose |
|------|---------|---------|
| **Go** | 1.25+ | Building KubeVigil from source (`go.mod` requires 1.25) |
| **kind** | 0.25+ | Creating local Kubernetes clusters (0.31+ recommended for K8s 1.35) |
| **kubectl** | 1.35+ | Interacting with clusters (should match cluster K8s version) |
| **bats-core** | 1.10+ | Running shell script tests |
| **Python 3** | 3.8+ | Running the validation script (`validate-findings.py`) |

### Optional (for cross-validation)

| Tool | Install | Purpose |
|------|---------|---------|
| **trivy** | `brew install trivy` | Cross-validate findings against Aqua's scanner |
| **kubescape** | `brew tap kubescape/tap && brew install kubescape` | Cross-validate against ARMO/CNCF scanner |
| **polaris** | `brew tap fairwindsops/tap && brew install polaris` | Cross-validate against Fairwinds' scanner |
| **kube-bench** | Runs as in-cluster Job (no host install needed) | CIS Kubernetes Benchmark checks |
| **helm** | `brew install helm` | Rendering third-party Helm charts for manifest-mode scanning |

### Install Prerequisites

```bash
# macOS (Homebrew)
brew install kind kubectl bats-core helm python3

# Go (if not already installed)
brew install go

# Build KubeVigil
cd /path/to/KubeVigil
make build
export PATH="$PWD/bin:$PATH"
```

---

## Quick Start — Full Suite

### Manifest Mode (No Cluster Required)

The fastest way to run the full E2E suite is in manifest mode, which scans YAML
files directly without requiring a running cluster:

```bash
# From the repository root
cd /path/to/KubeVigil

# Scan all scenarios at once
for scenario in test/e2e/scenarios/*/; do
  name=$(basename "$scenario")
  echo "=== Scanning scenario: $name ==="
  bin/kubevigil scan --file "$scenario" -o json > "test/e2e/scan-results/${name}.json" 2>&1
  echo "Exit code: $?"
  echo ""
done
```

### Live Mode (Requires Kind Cluster)

For full coverage including namespace-level and cluster-level checks:

```bash
# 1. Create a Kind cluster
kind create cluster --config test/e2e/clusters/kind-single-node.yaml

# 2. Deploy all scenarios
for scenario in test/e2e/scenarios/*/; do
  echo "=== Deploying: $(basename "$scenario") ==="
  kubectl apply -f "$scenario" 2>/dev/null || true
done

# 3. Wait for resources to settle
sleep 10

# 4. Run the scan
bin/kubevigil scan -o json > test/e2e/scan-results/live-full-scan.json
echo "Exit code: $?"

# 5. Clean up
kind delete cluster --name kubevigil-e2e-single
```

### Using the Automation Scripts

The scripts under `test/e2e/scripts/` automate the full workflow:

```bash
cd test/e2e

# Create cluster, deploy scenarios, scan, validate, and tear down
./scripts/full-suite.sh

# Or step by step:
./scripts/setup-clusters.sh --topology single
./scripts/deploy-scenarios.sh --scenario all --context kind-kubevigil-e2e-single
./scripts/run-scan.sh --context kind-kubevigil-e2e-single
./scripts/cross-validate.sh --context kind-kubevigil-e2e-single
./scripts/teardown-clusters.sh --all
```

---

## Running Individual Scenarios

### Manifest Mode

```bash
# Scan a single scenario directory
bin/kubevigil scan --file test/e2e/scenarios/workload-security/ -o text

# Scan a single manifest file
bin/kubevigil scan --file test/e2e/scenarios/rbac/wildcard-permissions.yaml -o text

# Output as JSON for programmatic assertion
bin/kubevigil scan --file test/e2e/scenarios/image-security/ -o json | \
  jq '.scan_result.findings | length'
```

### Live Mode

```bash
# Create the cluster
kind create cluster --config test/e2e/clusters/kind-single-node.yaml

# Deploy a single scenario
kubectl apply -f test/e2e/scenarios/network/

# Scan the scenario's namespace
bin/kubevigil scan --namespace kv-e2e-network -o text

# Clean up the namespace
kubectl delete namespace kv-e2e-network
```

### Using JSON Output for Assertions

KubeVigil's JSON output wraps findings under `.scan_result.findings`. Each
finding uses the field `.checker` (not `checkID`) for the check identifier.

```bash
# Count total findings
bin/kubevigil scan --file test/e2e/scenarios/rbac/ -o json | \
  jq '.scan_result.findings | length'

# List unique check IDs that fired
bin/kubevigil scan --file test/e2e/scenarios/rbac/ -o json | \
  jq '[.scan_result.findings[].checker] | unique'

# Count findings by severity
bin/kubevigil scan --file test/e2e/scenarios/rbac/ -o json | \
  jq '[.scan_result.findings[].severity] | group_by(.) | map({(.[0]): length}) | add'

# Verify a specific check fired
bin/kubevigil scan --file test/e2e/scenarios/rbac/ -o json | \
  jq '.scan_result.findings[] | select(.checker == "rbac-cluster-admin")'
```

---

## How to Add New Scenarios

### 1. Create the scenario directory

```bash
mkdir test/e2e/scenarios/<category-name>/
```

### 2. Create a namespace manifest (if needed)

```yaml
# test/e2e/scenarios/<category-name>/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: kv-e2e-<category>
  labels:
    app.kubernetes.io/part-of: kubevigil-e2e
    kubevigil.stribog.cloud/scenario: <category-name>
```

**Naming convention:** All E2E namespaces use the `kv-e2e-` prefix. This allows
bulk cleanup via `helpers.sh`'s `delete_e2e_namespaces` function.

### 3. Create manifests that trigger specific checks

Each manifest file should:
- Have a comment header documenting which checks it triggers and why.
- Use descriptive resource names that indicate the security issue.
- Include the `app.kubernetes.io/part-of: kubevigil-e2e` label.
- Use lightweight images (`registry.k8s.io/pause:3.9`) to minimize resource
  usage in live mode.
- Be self-contained (do not depend on resources from other scenarios).

### 4. Document expected findings

Add an entry to `test/e2e/expected/README.md` with:
- Check IDs that should trigger
- Expected minimum finding count
- Severity distribution
- Pass/fail criteria

### 5. Verify

```bash
# Manifest mode
bin/kubevigil scan --file test/e2e/scenarios/<category-name>/ -o json | \
  jq '[.scan_result.findings[].checker] | unique'

# Confirm expected checks appear in the output
```

---

## Scan Results

Scan results are stored in `test/e2e/scan-results/` (gitignored). The directory
is created automatically by the scan scripts.

```
test/e2e/scan-results/
|-- e2e-live-single-full.json       # Full live-cluster scan (JSON)
|-- e2e-live-single-full.html       # Full scan in other formats
|-- e2e-live-single-full.sarif
|-- e2e-live-single-full.csv
|-- e2e-live-single-full.xml
|-- e2e-live-single-full.yaml
|-- e2e-live-single-full.md
|-- e2e-live-single-full.txt
|-- e2e-live-ns-kv-e2e-*.json       # Per-namespace scan results
|-- e2e-live-cis.json               # Framework-filtered scans
|-- e2e-live-mitre.json
|-- e2e-live-nsa.json
|-- e2e-live-critical.json          # Severity-filtered scan
|-- e2e-live-system-ns.json         # Scan including system namespaces
+-- cross-validation/               # Third-party tool results
    |-- trivy-results.json
    |-- kubescape-results.json
    |-- polaris-results.json
    +-- kube-bench-results.json
```

---

## Cross-Validation

KubeVigil findings can be cross-validated against other KSPM tools to identify
false positives and false negatives. The `cross-validate.sh` script automates
this for trivy, kubescape, and polaris (kube-bench runs as an in-cluster Job).

See `test/e2e/third-party/README.md` for detailed instructions.

Quick example:

```bash
# Scan the same manifests with KubeVigil and Trivy
bin/kubevigil scan --file test/e2e/scenarios/workload-security/ -o json > /tmp/kv.json
trivy config test/e2e/scenarios/workload-security/ --format json > /tmp/trivy.json

# Compare finding counts
echo "KubeVigil: $(jq '.scan_result.findings | length' /tmp/kv.json) findings"
echo "Trivy:     $(jq '.Results | map(.Misconfigurations // [] | length) | add' /tmp/trivy.json) findings"
```

---

## Running Bats Tests

The `test/e2e/scripts/tests/` directory contains 93 Bats tests that validate
the E2E shell scripts and helper library.

### Prerequisites

```bash
# Install bats-core
brew install bats-core
# Or: npm install -g bats
```

### Running Bats Tests

```bash
# Run all Bats tests (93 tests)
bats test/e2e/scripts/tests/

# Run with verbose output
bats --verbose-run test/e2e/scripts/tests/

# Run a specific test file
bats test/e2e/scripts/tests/helpers.bats
```

### What the Bats Tests Cover

| File | Tests | Coverage |
|------|-------|----------|
| `helpers.bats` | 15 | Shared helper functions: logging, mocks, assertions, namespace management |
| `setup-clusters.bats` | 10 | Kind cluster creation, topology selection, prerequisite checks |
| `deploy-scenarios.bats` | 12 | Scenario deployment, namespace creation, selective deployment |
| `run-scan.bats` | 10 | Scan execution, output formats, exit codes, namespace filtering |
| `teardown-clusters.bats` | 8 | Cluster deletion, cleanup verification |
| `full-suite.bats` | 10 | End-to-end orchestration, error handling, partial runs |
| `cross-validate.bats` | 10 | Third-party tool detection, output capture, comparison |
| `fix.bats` | 18 | Fix command E2E: dry-run, apply, verify, risk levels, backups, partial failure |

### Adding New Bats Tests

Create a `.bats` file in `test/e2e/scripts/tests/`:

```bash
#!/usr/bin/env bats
# test/e2e/scripts/tests/my_new_test.bats

load test_helper

@test "my helper function works correctly" {
  run my_function "arg1"
  assert_exit_code 0
  assert_output_contains "expected output"
}
```

---

## Validation Script

The `validate-findings.py` script validates scan results against expected
finding counts per category:

```bash
# Validate all categories in live mode
python3 test/e2e/scripts/validate-findings.py \
  --all --mode live --results-dir test/e2e/scan-results/

# Validate a single category
python3 test/e2e/scripts/validate-findings.py \
  --category rbac --mode live --results-dir test/e2e/scan-results/
```

---

## Kind Cluster Configurations

Three cluster profiles are available under `test/e2e/clusters/`:

| Configuration | Nodes | Use Case |
|---------------|-------|----------|
| `kind-single-node.yaml` | 1 CP | Fast smoke tests. No multi-node topology. |
| `kind-multi-node.yaml` | 1 CP + 3 workers | Scheduling, topology spread, NetworkPolicy, node affinity. |
| `kind-ha-control-plane.yaml` | 3 CP + 2 workers | HA checks: etcd, API server config, component versions, control-plane tolerations. |

### Create a cluster

```bash
kind create cluster --config test/e2e/clusters/kind-single-node.yaml
```

### Delete a cluster

```bash
kind delete cluster --name kubevigil-e2e-single
kind delete cluster --name kubevigil-e2e-multi
kind delete cluster --name kubevigil-e2e-ha
```

### Cluster contexts

Kind clusters are accessible via the context `kind-<cluster-name>`:
- `kind-kubevigil-e2e-single`
- `kind-kubevigil-e2e-multi`
- `kind-kubevigil-e2e-ha`

---

## Known Limitations

1. **PodSecurityPolicy manifests are rejected on K8s 1.25+.** The
   `deprecated-apis.yaml` file in the cluster-hardening scenario contains a
   PodSecurityPolicy (policy/v1beta1), which was removed in Kubernetes 1.25.
   The API server will reject this resource in live mode. Use manifest mode
   (`--file`) to test the deprecated-api-usage checker.

2. **procMount: Unmasked requires a feature gate.** The `proc-mount.yaml`
   manifest sets `procMount: Unmasked`, which requires the `ProcMountType`
   feature gate on the API server. Kind clusters may not have this enabled by
   default. The manifest is accepted in manifest mode regardless.

3. **Registry checks require policy configuration.** The `image-registry-allowlist`
   and `image-registry-blocklist` checks are no-ops without a `.kubevigil.yaml`
   that defines `allowedRegistries` and/or `blockedRegistries`. When running E2E
   tests for these checks, supply a config file via `--config`.

4. **PVC reclaim-retain findings require Released PV state.** The
   `pvc-reclaim-retain` check fires when a PersistentVolume enters the Released
   state, which requires deleting the PVC while the PV uses the Retain policy.
   This condition does not occur from simply applying manifests.

5. **Namespace-level checks only fire in live mode.** Checks like
   `network-policy-missing`, `limit-range-missing`, and `resource-quota-missing`
   inspect cluster state, not individual manifests. They will not produce
   findings in manifest mode.

6. **Kind clusters lack cloud provider features.** Cloud-specific checks
   (`eks-imds-access`, `gke-metadata-concealment`, `aks-pod-identity`) will not
   produce findings on Kind clusters. These require real cloud provider node
   labels and configurations.

7. **Multi-node topology checks need the multi-node cluster.** Checks like
   `topology-spread` and `node-affinity-untrusted` require multiple worker nodes
   to be meaningful. Use `kind-multi-node.yaml` for these tests.

8. **The `clean` scenario contains a fully hardened deployment.** The
   `clean/hardened-deployment.yaml` manifest defines a namespace with full PSA
   enforcement, NetworkPolicy, ResourceQuota, LimitRange, PDB, PriorityClass,
   custom ServiceAccount, and a pod spec with every security field explicitly
   set to the secure value. It must produce zero findings — any finding is a
   false positive.

---

## CI Integration

### GitHub Actions Example

```yaml
jobs:
  e2e-manifest:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.25'
      - run: make build
      - name: Run manifest-mode E2E
        run: |
          for scenario in test/e2e/scenarios/*/; do
            name=$(basename "$scenario")
            echo "::group::$name"
            bin/kubevigil scan --file "$scenario" -o json > "/tmp/${name}.json" 2>&1 || true
            findings=$(jq '.scan_result.findings | length' "/tmp/${name}.json" 2>/dev/null || echo "parse error")
            echo "Findings: $findings"
            echo "::endgroup::"
          done

  e2e-live:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.25'
      - run: make build
      - name: Create Kind cluster
        uses: helm/kind-action@v1
        with:
          config: test/e2e/clusters/kind-single-node.yaml
          cluster_name: kubevigil-e2e-single
      - name: Deploy scenarios
        run: |
          for scenario in test/e2e/scenarios/*/; do
            kubectl apply -f "$scenario" 2>/dev/null || true
          done
          sleep 10
      - name: Run live scan
        run: bin/kubevigil scan -o json > /tmp/live-scan.json
      - name: Verify findings
        run: |
          count=$(jq '.scan_result.findings | length' /tmp/live-scan.json)
          echo "Total findings: $count"
          if [ "$count" -lt 50 ]; then
            echo "ERROR: Expected at least 50 findings, got $count"
            exit 1
          fi
```

---

## Fix Command E2E Tests

Phase 3 introduced the `kubevigil fix` command for auto-remediation. These E2E
tests validate the full fix workflow end-to-end.

### Fix Scenarios

| Scenario | Purpose | Manifests |
|----------|---------|-----------|
| `fix-safe` | Safe-level fixes (privileged, privilege-escalation, host-pid/ipc) | 3 files |
| `fix-moderate` | Likely-safe fixes (runAsNonRoot, readOnlyRootFilesystem, drop ALL) | 2 files |
| `fix-aggressive` | Potentially-breaking fixes (resource limits, hostPort removal) | 3 files |
| `fix-system-ns` | System namespace protection (kube-system resources skipped) | 1 file |
| `fix-known-workloads` | Known workload detection (Calico, CoreDNS, node-exporter) | 3 files |
| `fix-multi-doc` | Multi-document YAML handling (3 docs, only 2 modified) | 1 file |
| `fix-comments` | YAML comment preservation through round-trip patching | 1 file |
| `fix-clean` | Hardened deployment (exit code 4 — nothing to fix) | 1 file |
| `fix-partial-failure` | Partial failure resilience (valid + malformed + readonly) | 3 files |

### Running Fix E2E Tests

```bash
# Bats tests (18 tests, requires built binary)
make build
bats test/e2e/scripts/tests/fix.bats

# Manifest-mode E2E (builds binary automatically)
./test/e2e/scripts/run-fix.sh

# Skip build if binary exists
./test/e2e/scripts/run-fix.sh --skip-build

# Live cluster E2E (requires Kind)
./test/e2e/scripts/run-fix-live.sh

# Validate fix results with Python script
python3 test/e2e/scripts/validate-findings.py \
  --mode fix --pre-scan /tmp/pre.json --post-scan /tmp/post.json --risk-level safe
```

### Golden Workflow

The golden E2E workflow validates the core fix promise:

```
scan → fix --apply --verify → re-scan → reduced findings
```

Both `run-fix.sh` (Test 8) and `fix.bats` (tests 2, 3, 18) exercise this path.

### Fix Exit Codes

| Code | Meaning | Tested By |
|------|---------|-----------|
| 0 | All fixes applied (or dry-run shows changes) | Tests 1, 2, 3 |
| 1 | Fixes applied but --verify found remaining findings | Test 3 |
| 3 | Configuration error (CI mode without --yes) | Test 12 |
| 4 | No fixable findings (clean scenario) | Test 7 |
| 5 | Partial success (some files failed) | Tests 15, 16 |
