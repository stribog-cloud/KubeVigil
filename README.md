# KubeVigil

**Know your clusters before attackers do.**

KubeVigil is a Kubernetes Security Posture Management (KSPM) CLI tool that scans clusters and YAML manifests for security misconfigurations. It checks workloads against 25 security best practices covering privileged containers, capabilities, root access, resource limits, host namespace exposure, and more.

## Installation

```bash
go install github.com/stribog-cloud/kubevigil/cmd/kubevigil@latest
```

Or build from source:

```bash
git clone https://github.com/stribog-cloud/kubevigil.git
cd kubevigil
make build
# Binary at ./bin/kubevigil
```

## Quick Start

### Scan YAML manifests

```bash
# Scan a single file
kubevigil scan --file deployment.yaml

# Scan a directory of manifests
kubevigil scan --file ./manifests/

# Output as JSON
kubevigil scan --file ./manifests/ -o json
```

### Scan a live cluster

```bash
# Uses current kubeconfig context
kubevigil scan

# Specify kubeconfig and context
kubevigil scan --kubeconfig ~/.kube/config --context production
```

### List available checks

```bash
kubevigil list checks
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Clean scan, no findings above fail-on threshold |
| 1 | Findings at or above the fail-on severity |
| 2 | Scan error (bad path, cluster unreachable, etc.) |
| 3 | Configuration error (invalid config file) |

## Configuration

Create a `.kubevigil.yaml` in your project root (see `configs/kubevigil.example.yaml`):

```yaml
version: "1"

settings:
  severity_threshold: info   # Minimum severity to report
  fail_on: high              # Minimum severity for exit code 1
  concurrency: 10            # Max parallel checks
  timeout: 5m

checks:
  disabled:
    - runtime-class          # Disable specific checks
  overrides:
    privileged:
      severity: high         # Override default severity

exemptions:
  - namespace: kube-system
    reason: "System namespace"
    approved_by: "platform-team"
```

### Annotation-based exemptions

Add the `kubevigil.io/skip` annotation to skip checks on specific resources:

```yaml
metadata:
  annotations:
    kubevigil.io/skip: "*"                    # Skip all checks
    kubevigil.io/skip: "privileged,host-pid"  # Skip specific checks
```

## Phase 1 Checks (25 total)

| # | Check ID | What It Detects | Default Severity |
|---|----------|----------------|-----------------|
| 1 | `privileged` | Containers running in privileged mode | Critical |
| 2 | `capabilities-added` | Dangerous Linux capabilities added | High |
| 3 | `capabilities-not-dropped` | Not dropping ALL capabilities | Medium |
| 4 | `run-as-root` | Running as root or missing runAsNonRoot | High |
| 5 | `run-as-high-uid` | UID below 10000 | Low |
| 6 | `run-as-group` | Missing runAsGroup or GID 0 | Medium |
| 7 | `read-only-rootfs` | Missing readOnlyRootFilesystem | Medium |
| 8 | `resource-limits-missing` | Missing CPU or memory limits | Medium |
| 9 | `resource-requests-missing` | Missing CPU or memory requests | Medium |
| 10 | `resource-limits-ratio` | Limits/requests ratio > 3x | Low |
| 11 | `ephemeral-storage-limits` | Missing ephemeral-storage limits | Low |
| 12 | `host-pid` | hostPID enabled | Critical |
| 13 | `host-ipc` | hostIPC enabled | Critical |
| 14 | `host-network` | hostNetwork enabled | Critical |
| 15 | `host-ports` | Containers binding host ports | High |
| 16 | `host-path-volumes` | hostPath volume mounts | Critical-Medium |
| 17 | `privilege-escalation` | Missing allowPrivilegeEscalation: false | High |
| 18 | `seccomp-profile` | Missing Seccomp profile | Medium |
| 19 | `apparmor-profile` | Missing AppArmor profile | Medium |
| 20 | `selinux-options` | SELinux misconfigurations | Medium |
| 21 | `proc-mount` | procMount: Unmasked | High |
| 22 | `unsafe-sysctls` | Unsafe sysctl configuration | High |
| 23 | `runtime-class` | Missing RuntimeClass | Low |
| 24 | `share-process-namespace` | shareProcessNamespace enabled | Medium |
| 25 | `ephemeral-container-policy` | Ephemeral containers without security restrictions | Medium |

All workload checks cover regular containers, init containers, and native sidecar containers (K8s 1.28+).

## CLI Reference

```
kubevigil scan [flags]
  -f, --file string              Path to YAML file or directory (manifest mode)
      --kubeconfig string        Path to kubeconfig file
      --context string           Kubeconfig context to use
  -n, --namespace string         Scan only this namespace
      --exclude-namespace string Exclude this namespace
      --severity string          Minimum severity to report
      --fail-on string           Minimum severity for exit code 1
      --concurrency int          Max concurrent checks
  -o, --output string            Output format: text, json (default "text")
      --config string            Config file path (default: auto-discover)
      --no-color                 Disable colored output
  -v, --verbose                  Enable verbose logging
```

## Development

```bash
make build       # Build binary
make test        # Run all tests with race detection
make lint        # Run golangci-lint
make vet         # Run go vet
make check       # Run all quality gates (vet + lint + test)
make test-cover  # Generate coverage report
make clean       # Remove build artifacts
```

## License

Apache 2.0 - See [LICENSE](LICENSE) for details.
