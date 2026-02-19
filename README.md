# KubeVigil

**Know your clusters before attackers do.**

KubeVigil is a Kubernetes Security Posture Management (KSPM) CLI tool that scans clusters and YAML manifests for security misconfigurations. It runs **110 security checks** across **13 categories**, maps findings to industry compliance frameworks (CIS, MITRE ATT&CK, NSA/CISA), and outputs reports in 8 formats.

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

# Output as Markdown (great for PRs)
kubevigil scan --file ./manifests/ -o markdown

# Output as SARIF (GitHub Security tab)
kubevigil scan --file ./manifests/ -o sarif > results.sarif

# Output as HTML report
kubevigil scan --file ./manifests/ -o html > report.html

# Output as JUnit XML (CI systems)
kubevigil scan --file ./manifests/ -o junit > results.xml

# Output as CSV (spreadsheet analysis)
kubevigil scan --file ./manifests/ -o csv > results.csv

# Output as YAML
kubevigil scan --file ./manifests/ -o yaml
```

### Scan a live cluster

```bash
# Uses current kubeconfig context
kubevigil scan

# Specify kubeconfig and context
kubevigil scan --kubeconfig ~/.kube/config --context production
```

### Filter by compliance framework

```bash
# Show only CIS Kubernetes Benchmark findings
kubevigil scan --file ./manifests/ --framework cis

# Show only MITRE ATT&CK mapped findings
kubevigil scan --file ./manifests/ --framework mitre

# Show only NSA/CISA Hardening Guide findings
kubevigil scan --file ./manifests/ --framework nsa

# Combine with output format
kubevigil scan --framework cis -o markdown > cis-report.md
```

### List available checks

```bash
kubevigil list checks
```

## Security Checks (110 total)

### Workload Security (25 checks)

Pod and container security — privileged mode, capabilities, root access, resource limits, host namespace exposure, security profiles.

| # | Check ID | Default Severity |
|---|----------|-----------------|
| 1 | `privileged` | Critical |
| 2 | `capabilities-added` | High |
| 3 | `capabilities-not-dropped` | Medium |
| 4 | `run-as-root` | High |
| 5 | `run-as-high-uid` | Low |
| 6 | `run-as-group` | Medium |
| 7 | `read-only-rootfs` | Medium |
| 8 | `resource-limits-missing` | Medium |
| 9 | `resource-requests-missing` | Medium |
| 10 | `resource-limits-ratio` | Low |
| 11 | `ephemeral-storage-limits` | Low |
| 12 | `host-pid` | Critical |
| 13 | `host-ipc` | Critical |
| 14 | `host-network` | Critical |
| 15 | `host-ports` | High |
| 16 | `host-path-volumes` | Critical |
| 17 | `privilege-escalation` | High |
| 18 | `seccomp-profile` | Medium |
| 19 | `apparmor-profile` | Medium |
| 20 | `selinux-options` | Medium |
| 21 | `proc-mount` | High |
| 22 | `unsafe-sysctls` | High |
| 23 | `runtime-class` | Low |
| 24 | `share-process-namespace` | Medium |
| 25 | `ephemeral-container-policy` | Medium |

All workload checks cover regular containers, init containers, and native sidecar containers (K8s 1.28+).

### Image Security (9 checks)

Image tag hygiene, digest pinning, registry allow/block lists, signature verification, SBOM attestation, provenance.

| # | Check ID | Default Severity |
|---|----------|-----------------|
| 26 | `image-tag-latest` | Medium |
| 27 | `image-tag-missing` | Medium |
| 28 | `image-no-digest` | Low |
| 29 | `image-pull-policy` | Medium |
| 30 | `image-registry-allowlist` | High |
| 31 | `image-registry-blocklist` | Critical |
| 32 | `image-signature-verification` | Medium |
| 33 | `image-sbom-attestation` | Low |
| 34 | `image-provenance` | Low |

### Identity & Access — RBAC (15 checks)

Service account hygiene, RBAC wildcard rules, privilege escalation verbs, secret access, cluster-admin bindings.

| # | Check ID | Default Severity |
|---|----------|-----------------|
| 35 | `default-service-account` | High |
| 36 | `automount-token` | High |
| 37 | `token-projection-config` | Medium |
| 38 | `rbac-wildcard-verbs` | Critical |
| 39 | `rbac-wildcard-resources` | Critical |
| 40 | `rbac-wildcard-apigroups` | Critical |
| 41 | `rbac-escalation-verbs` | Critical |
| 42 | `rbac-secret-access` | High |
| 43 | `rbac-exec-access` | High |
| 44 | `rbac-log-access` | Medium |
| 45 | `rbac-cluster-admin` | Critical |
| 46 | `rbac-unused-roles` | Info |
| 47 | `rbac-group-bindings` | High |
| 48 | `rbac-subject-external` | Low |
| 49 | `cloud-iam-binding` | Medium |

### Secrets Management (7 checks)

Secrets in environment variables, unencrypted etcd, secrets in ConfigMaps (entropy analysis), hardcoded credentials.

| # | Check ID | Default Severity |
|---|----------|-----------------|
| 50 | `secrets-in-env` | Medium |
| 51 | `secrets-unencrypted` | Critical |
| 52 | `secrets-in-configmap` | High |
| 53 | `secrets-default-type` | Low |
| 54 | `secrets-stale` | Medium |
| 55 | `secrets-hardcoded-manifests` | High |
| 56 | `external-secrets-sync` | Medium |

### Network Security (12 checks)

NetworkPolicy enforcement, ingress TLS, service exposure, service mesh mTLS, DNS security.

| # | Check ID | Default Severity |
|---|----------|-----------------|
| 57 | `network-policy-missing` | High |
| 58 | `network-policy-default-deny` | High |
| 59 | `network-policy-overly-permissive` | Medium |
| 60 | `network-policy-egress-unrestricted` | Medium |
| 61 | `ingress-no-tls` | High |
| 62 | `ingress-wildcard-host` | Medium |
| 63 | `ingress-class-missing` | Low |
| 64 | `service-type-loadbalancer` | Medium |
| 65 | `service-type-nodeport` | Medium |
| 66 | `external-ips` | High |
| 67 | `service-mesh-mtls` | High |
| 68 | `dns-security` | Medium |

### Pod Security Standards (6 checks)

PSA label enforcement, PSS profile validation, PSP migration detection.

| # | Check ID | Default Severity |
|---|----------|-----------------|
| 69 | `psa-labels-missing` | Medium |
| 70 | `psa-mode-audit-only` | Medium |
| 71 | `psa-baseline-violations` | High |
| 72 | `psa-restricted-violations` | Medium |
| 73 | `psa-version-pinning` | Low |
| 74 | `psp-still-present` | Info |

### Scheduling & Availability (8 checks)

Tolerations, PriorityClass abuse, PodDisruptionBudgets, topology spread, HPA configuration.

| # | Check ID | Default Severity |
|---|----------|-----------------|
| 75 | `toleration-control-plane` | High |
| 76 | `toleration-all` | Medium |
| 77 | `priority-class-system` | High |
| 78 | `priority-class-missing` | Low |
| 79 | `pod-disruption-budget` | Low |
| 80 | `topology-spread` | Low |
| 81 | `node-affinity-untrusted` | Medium |
| 82 | `hpa-without-requests` | Medium |

### Storage Security (5 checks)

PVC encryption, reclaim policies, CSI driver security, emptyDir limits, projected volume security.

| # | Check ID | Default Severity |
|---|----------|-----------------|
| 83 | `pvc-no-encryption` | Medium |
| 84 | `pvc-reclaim-retain` | Medium |
| 85 | `csi-driver-security` | Low |
| 86 | `emptydir-size-limit` | Low |
| 87 | `projected-volume-security` | Medium |

### Cluster Configuration (10 checks)

Namespace hygiene, LimitRange/ResourceQuota enforcement, API server settings, etcd encryption, kubelet config.

| # | Check ID | Default Severity |
|---|----------|-----------------|
| 88 | `namespace-default-usage` | Medium |
| 89 | `limit-range-missing` | Low |
| 90 | `resource-quota-missing` | Low |
| 91 | `api-server-anonymous` | High |
| 92 | `audit-logging` | High |
| 93 | `admission-controllers` | Medium |
| 94 | `etcd-encryption` | Critical |
| 95 | `kubelet-config` | High |
| 96 | `component-versions` | Medium |
| 97 | `deprecated-api-usage` | Medium |

### Supply Chain (5 checks)

Container runtime socket exposure, liveness/readiness/startup probes, lifecycle hooks, image age.

| # | Check ID | Default Severity |
|---|----------|-----------------|
| 98 | `container-runtime-socket` | Critical |
| 99 | `liveness-readiness-probes` | Low |
| 100 | `startup-probes` | Info |
| 101 | `lifecycle-hooks` | Low |
| 102 | `image-age` | Low |

### Cloud Provider (4 checks)

EKS IMDS access, GKE metadata concealment, AKS pod identity, cloud provider auto-detection. Live cluster only.

| # | Check ID | Default Severity |
|---|----------|-----------------|
| 103 | `eks-imds-access` | High |
| 104 | `gke-metadata-concealment` | High |
| 105 | `aks-pod-identity` | Medium |
| 106 | `cloud-provider-detection` | Info |

### CRD Security (4 checks)

CRD validation schemas, conversion webhooks, cert-manager certificate expiry and insecure key algorithms.

| # | Check ID | Default Severity |
|---|----------|-----------------|
| 107 | `crd-validation-missing` | Medium |
| 108 | `crd-conversion-webhook` | High |
| 109 | `cert-manager-expiry` | High |
| 110 | `cert-manager-insecure` | Medium |

## Compliance Framework Mapping

Every finding is mapped to one or more industry compliance frameworks:

| Framework | Version | Description |
|-----------|---------|-------------|
| CIS Kubernetes Benchmark | v1.8 | Industry-standard Kubernetes hardening controls |
| MITRE ATT&CK for Containers | v14 | Attacker tactics and techniques mapping |
| NSA/CISA Kubernetes Hardening Guide | v1.2 | US government hardening guidance |

Use `--framework` to filter reports to a specific framework:

```bash
kubevigil scan --file ./manifests/ --framework cis
kubevigil scan --framework mitre -o sarif > mitre-findings.sarif
```

## Output Formats

| Format | Flag | Use Case |
|--------|------|----------|
| Text | `-o text` | Human-readable colored terminal output (default) |
| JSON | `-o json` | Machine-readable structured output |
| Markdown | `-o markdown` | PRs, wikis, documentation |
| SARIF 2.1.0 | `-o sarif` | GitHub Security tab, Azure DevOps, VS Code |
| YAML | `-o yaml` | Kubernetes-native tooling |
| HTML | `-o html` | Self-contained report with inline CSS |
| JUnit XML | `-o junit` | CI systems (Jenkins, GitLab, etc.) |
| CSV | `-o csv` | Spreadsheet analysis |

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
      --framework string         Filter by compliance framework (cis, mitre, nsa)
      --concurrency int          Max concurrent checks
  -o, --output string            Output format: text, json, markdown, yaml, html, sarif, junit, csv (default "text")
      --config string            Config file path (default: auto-discover)
      --no-color                 Disable colored output
  -v, --verbose                  Enable verbose logging
```

## Roadmap

- [x] **Phase 1** — Core engine, 25 workload checks, text/JSON output, CLI, configuration
- [x] **Phase 2** — 85 additional checks (110 total), 6 new output formats, CIS/MITRE/NSA framework mapping
- [ ] **Phase 3** — Auto-remediation (`kubevigil fix`)
- [ ] **Phase 4** — GitHub Action, baseline management, PR decoration
- [ ] **Phase 5** — Admission webhooks, operator mode, Prometheus metrics
- [ ] **Phase 6** — Multi-cluster, trend analysis, Rego policies
- [ ] **Phase 7** — SDK, plugin system, Helm/Krew/Homebrew distribution

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
