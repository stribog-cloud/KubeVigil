# KubeVigil

![Coverage](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/msambare/1248dd902276859b5cdea636aa5ba175/raw/kubevigil-coverage.json)

**Know your clusters before attackers do.**

KubeVigil is a Kubernetes Security Posture Management (KSPM) CLI tool that
scans clusters and YAML manifests for security misconfigurations. It runs
**110 security checks** across **12 categories**, maps every finding to
industry compliance frameworks (CIS Kubernetes Benchmark, MITRE ATT&CK,
NSA/CISA), and outputs reports in 8 formats — from colored terminal text to
SARIF for GitHub Security.

## Why KubeVigil

- **Single binary, zero dependencies.** No agents, no sidecars, no cluster
  components to install. Point it at a kubeconfig or a directory of YAML files
  and get results in seconds.
- **110 checks, 12 categories.** Covers workload security, RBAC, network
  policies, secrets management, Pod Security Standards, scheduling, storage,
  cluster configuration, supply chain, cloud provider specifics, and CRD
  security.
- **Dual-mode scanning.** Scan live clusters (reads the Kubernetes API) or
  static YAML manifests (no cluster required). 94 checks work in both modes,
  15 are live-only (they inspect cluster state that doesn't exist in YAML),
  and 1 is manifest-only.
- **Compliance framework mapping.** Every finding maps to CIS Kubernetes
  Benchmark v1.8, MITRE ATT&CK for Containers v14, and NSA/CISA Kubernetes
  Hardening Guide v1.2. Filter reports by framework with `--framework`.
- **8 output formats.** Text, JSON, Markdown, SARIF 2.1.0, YAML, HTML, JUnit
  XML, and CSV. Write directly to a file with `-o report.html`.
- **Actionable remediation.** Each finding includes a detailed remediation
  guide explaining why the issue matters, what to do about it, and a
  ready-to-use YAML snippet.
- **Configurable and exemptible.** Disable checks, override severities, exempt
  namespaces, or skip individual resources with annotations — all via a single
  `.kubevigil.yaml` config file.
- **CI-ready exit codes.** Exit 0 for clean, exit 1 when findings exceed a
  configurable severity threshold, exit 2 for scan errors, exit 3 for config
  errors.

---

## Installation

**Requirements:** Go 1.25 or later.

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

---

## Quick Start

### Scan YAML Manifests

No cluster required — KubeVigil parses manifests directly:

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

# Write directly to a file (format inferred from extension)
kubevigil scan --file ./manifests/ -o report.html
kubevigil scan --file ./manifests/ -o findings.csv
```

### Scan a Live Cluster

KubeVigil reads your kubeconfig just like `kubectl`. If `kubectl` works,
`kubevigil scan` works — no additional setup needed:

```bash
# Scan the cluster in your current kubeconfig context
kubevigil scan

# Same thing, explicitly — useful in scripts
kubevigil scan --kubeconfig ~/.kube/config

# Specify a context (e.g. scan staging, not production)
kubevigil scan --context staging

# Both kubeconfig and context
kubevigil scan --kubeconfig ~/.kube/config --context production

# Scan only a specific namespace
kubevigil scan --namespace my-app

# Exclude a namespace
kubevigil scan --exclude-namespace monitoring

# Exclude common infrastructure namespaces (monitoring, rook-ceph, calico, etc.)
kubevigil scan --exclude-infra

# Include system namespaces (kube-system, kube-public, kube-node-lease)
kubevigil scan --include-system-namespaces
```

In live mode, KubeVigil connects to the Kubernetes API server, discovers all
resources (Deployments, DaemonSets, StatefulSets, CronJobs, Roles, Bindings,
Services, Ingresses, ConfigMaps, Secrets, Namespaces, Nodes, etc.), and runs
all 110 checks including the 15 that require live cluster state — checks for
missing NetworkPolicies, missing ResourceQuotas, stale Secrets, unused RBAC
roles, etcd encryption status, and more.

### Filter by Compliance Framework

```bash
# Show only CIS Kubernetes Benchmark findings
kubevigil scan --framework cis

# Show only MITRE ATT&CK mapped findings
kubevigil scan --framework mitre

# Show only NSA/CISA Hardening Guide findings
kubevigil scan --framework nsa

# Combine with any output format
kubevigil scan --framework cis -o markdown > cis-report.md
```

### Filter by Severity

```bash
# Show only High and Critical findings
kubevigil scan --severity high

# Fail CI only on Critical findings
kubevigil scan --fail-on critical
```

### List Available Checks

```bash
kubevigil list checks
```

---

## How It Works

```
                ┌─────────────────────┐
                │   kubevigil scan    │
                │  --file / --context │
                └─────────┬───────────┘
                          │
              ┌───────────┴───────────┐
              ▼                       ▼
    ┌──────────────────┐    ┌──────────────────┐
    │  Manifest Mode   │    │   Live Mode      │
    │  Parse YAML/JSON │    │  K8s API client  │
    │  from disk       │    │  discovers all   │
    │                  │    │  resources       │
    └────────┬─────────┘    └────────┬─────────┘
             │                       │
             └───────────┬───────────┘
                         ▼
              ┌──────────────────────┐
              │   Check Engine       │
              │  110 checks run in   │
              │  parallel (default   │
              │  concurrency: 10)    │
              └──────────┬───────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │  Finding Aggregation │
              │  + Framework Mapping │
              │  (CIS / MITRE / NSA) │
              └──────────┬───────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │   Report Renderer    │
              │  text / json / html  │
              │  sarif / md / yaml   │
              │  csv / junit         │
              └──────────────────────┘
```

1. **Resource discovery.** In manifest mode, KubeVigil parses YAML files from
   disk (supports multi-document files). In live mode, it connects to the
   Kubernetes API server via the kubeconfig and discovers all relevant
   resources — workloads, RBAC objects, Services, NetworkPolicies, Namespaces,
   Nodes, and more.

2. **Check execution.** The engine runs all applicable checks in parallel
   against the discovered resources. Each check inspects specific fields
   (e.g., `securityContext.privileged`, `spec.containers[].resources.limits`)
   and produces zero or more findings. Checks handle regular containers, init
   containers, and native sidecar containers (K8s 1.28+ `restartPolicy:
   Always`).

3. **Finding enrichment.** Each finding is enriched with compliance framework
   mappings (CIS control IDs, MITRE technique IDs, NSA/CISA sections), a
   severity rating, the exact field path that triggered the finding, and a
   detailed remediation guide with YAML fix snippets.

4. **Report output.** Findings are rendered in the requested output format.
   The text formatter produces colored, grouped terminal output. JSON provides
   the full structured data. SARIF integrates with GitHub Security, VS Code,
   and Azure DevOps.

---

## JSON Output Structure

KubeVigil's JSON output has this structure:

```json
{
  "version": "1",
  "tool_version": "v0.2.0",
  "scan_result": {
    "summary": {
      "total_findings": 42,
      "critical": 3,
      "high": 12,
      "medium": 18,
      "low": 8,
      "info": 1,
      "posture_score": 65.2,
      "unique_resources": 15,
      "unique_namespaces": 4,
      "check_coverage": "80/110"
    },
    "findings": [
      {
        "checker": "privileged",
        "severity": "Critical",
        "resource": "debug-pod",
        "kind": "Pod",
        "message": "Container \"debug\" runs in privileged mode ...",
        "remediation": "## Why This Matters\n...",
        "field_path": "spec.containers[0].securityContext.privileged",
        "frameworks": {
          "cis": ["5.2.1"],
          "mitre": ["T1611"],
          "nsa": ["3.1"]
        }
      }
    ],
    "cluster_info": {
      "server_version": "v1.35.0",
      "node_count": 4,
      "namespace_count": 12,
      "context_name": "kind-kubevigil-e2e-single"
    },
    "scan_meta": {
      "scan_mode": "live",
      "start_time": "2026-02-17T06:30:00Z",
      "duration": "2.3s",
      "checks_run": 110,
      "checks_skipped": 0,
      "checks_errored": 0
    }
  }
}
```

Use `jq` to extract data:

```bash
# Count total findings
kubevigil scan -o json | jq '.scan_result.findings | length'

# List unique checks that fired
kubevigil scan -o json | jq '[.scan_result.findings[].checker] | unique'

# Count findings by severity
kubevigil scan -o json | jq '.scan_result.summary | {critical, high, medium, low, info}'

# Get the posture score
kubevigil scan -o json | jq '.scan_result.summary.posture_score'

# Filter findings for a specific check
kubevigil scan -o json | jq '.scan_result.findings[] | select(.checker == "privileged")'
```

---

## Security Checks (110 total)

### Workload Security (24 checks)

Pod and container security — privileged mode, capabilities, root access,
resource limits, host namespace exposure, security profiles. All checks cover
regular containers, init containers, and native sidecar containers (K8s 1.28+).

| # | Check ID | Default Severity | Modes |
|---|----------|-----------------|-------|
| 1 | `privileged` | Critical | Live, Manifest |
| 2 | `capabilities-added` | High | Live, Manifest |
| 3 | `capabilities-not-dropped` | Medium | Live, Manifest |
| 4 | `run-as-root` | High | Live, Manifest |
| 5 | `run-as-high-uid` | Low | Live, Manifest |
| 6 | `run-as-group` | Medium | Live, Manifest |
| 7 | `read-only-rootfs` | Medium | Live, Manifest |
| 8 | `resource-limits-missing` | Medium | Live, Manifest |
| 9 | `resource-requests-missing` | Medium | Live, Manifest |
| 10 | `resource-limits-ratio` | Low | Live, Manifest |
| 11 | `ephemeral-storage-limits` | Low | Live, Manifest |
| 12 | `host-pid` | Critical | Live, Manifest |
| 13 | `host-ipc` | Critical | Live, Manifest |
| 14 | `host-network` | Critical | Live, Manifest |
| 15 | `host-ports` | High | Live, Manifest |
| 16 | `host-path-volumes` | Critical | Live, Manifest |
| 17 | `privilege-escalation` | High | Live, Manifest |
| 18 | `seccomp-profile` | Medium | Live, Manifest |
| 19 | `apparmor-profile` | Medium | Live, Manifest |
| 20 | `selinux-options` | Medium | Live, Manifest |
| 21 | `proc-mount` | High | Live, Manifest |
| 22 | `unsafe-sysctls` | High | Live, Manifest |
| 23 | `runtime-class` | Low | Live, Manifest |
| 24 | `share-process-namespace` | Medium | Live, Manifest |

### Image Security (9 checks)

Image tag hygiene, digest pinning, registry allow/block lists, signature
verification, SBOM attestation, provenance.

| # | Check ID | Default Severity | Modes |
|---|----------|-----------------|-------|
| 25 | `image-tag-latest` | Medium | Live, Manifest |
| 26 | `image-tag-missing` | Medium | Live, Manifest |
| 27 | `image-no-digest` | Low | Live, Manifest |
| 28 | `image-pull-policy` | Medium | Live, Manifest |
| 29 | `image-registry-allowlist` | High | Live, Manifest |
| 30 | `image-registry-blocklist` | Critical | Live, Manifest |
| 31 | `image-signature-verification` | Medium | Live, Manifest |
| 32 | `image-sbom-attestation` | Low | Live, Manifest |
| 33 | `image-provenance` | Low | Live, Manifest |

### Identity & Access — RBAC (15 checks)

Service account hygiene, RBAC wildcard rules, privilege escalation verbs,
secret access, cluster-admin bindings.

| # | Check ID | Default Severity | Modes |
|---|----------|-----------------|-------|
| 34 | `default-service-account` | High | Live, Manifest |
| 35 | `automount-token` | High | Live, Manifest |
| 36 | `token-projection-config` | Medium | Live, Manifest |
| 37 | `rbac-wildcard-verbs` | Critical | Live, Manifest |
| 38 | `rbac-wildcard-resources` | Critical | Live, Manifest |
| 39 | `rbac-wildcard-apigroups` | Critical | Live, Manifest |
| 40 | `rbac-escalation-verbs` | Critical | Live, Manifest |
| 41 | `rbac-secret-access` | High | Live, Manifest |
| 42 | `rbac-exec-access` | High | Live, Manifest |
| 43 | `rbac-log-access` | Medium | Live, Manifest |
| 44 | `rbac-cluster-admin` | Critical | Live, Manifest |
| 45 | `rbac-unused-roles` | Info | Live, Manifest |
| 46 | `rbac-group-bindings` | High | Live, Manifest |
| 47 | `rbac-subject-external` | Low | Live, Manifest |
| 48 | `cloud-iam-binding` | Medium | Live, Manifest |

### Secrets Management (7 checks)

Secrets in environment variables, unencrypted etcd, high-entropy values in
ConfigMaps, hardcoded credentials in manifests.

| # | Check ID | Default Severity | Modes |
|---|----------|-----------------|-------|
| 49 | `secrets-in-env` | Medium | Live, Manifest |
| 50 | `secrets-unencrypted` | Critical | Live only |
| 51 | `secrets-in-configmap` | High | Live, Manifest |
| 52 | `secrets-default-type` | Low | Live, Manifest |
| 53 | `secrets-stale` | Medium | Live only |
| 54 | `secrets-hardcoded-manifests` | High | Manifest only |
| 55 | `external-secrets-sync` | Medium | Live only |

### Network Security (12 checks)

NetworkPolicy enforcement, ingress TLS, service exposure, service mesh mTLS,
DNS security.

| # | Check ID | Default Severity | Modes |
|---|----------|-----------------|-------|
| 56 | `network-policy-missing` | High | Live, Manifest |
| 57 | `network-policy-default-deny` | High | Live, Manifest |
| 58 | `network-policy-overly-permissive` | Medium | Live, Manifest |
| 59 | `network-policy-egress-unrestricted` | Medium | Live, Manifest |
| 60 | `ingress-no-tls` | High | Live, Manifest |
| 61 | `ingress-wildcard-host` | Medium | Live, Manifest |
| 62 | `ingress-class-missing` | Low | Live, Manifest |
| 63 | `service-type-loadbalancer` | Medium | Live, Manifest |
| 64 | `service-type-nodeport` | Medium | Live, Manifest |
| 65 | `external-ips` | High | Live, Manifest |
| 66 | `service-mesh-mtls` | High | Live, Manifest |
| 67 | `dns-security` | Medium | Live, Manifest |

### Pod Security Standards (6 checks)

PSA label enforcement, PSS profile validation, PSP migration detection.

| # | Check ID | Default Severity | Modes |
|---|----------|-----------------|-------|
| 68 | `psa-labels-missing` | Medium | Live, Manifest |
| 69 | `psa-mode-audit-only` | Medium | Live, Manifest |
| 70 | `psa-baseline-violations` | High | Live, Manifest |
| 71 | `psa-restricted-violations` | Medium | Live, Manifest |
| 72 | `psa-version-pinning` | Low | Live, Manifest |
| 73 | `psp-still-present` | Info | Live, Manifest |

### Scheduling & Availability (8 checks)

Tolerations, PriorityClass abuse, PodDisruptionBudgets, topology spread, HPA
configuration.

| # | Check ID | Default Severity | Modes |
|---|----------|-----------------|-------|
| 74 | `toleration-control-plane` | High | Live, Manifest |
| 75 | `toleration-all` | Medium | Live, Manifest |
| 76 | `priority-class-system` | High | Live, Manifest |
| 77 | `priority-class-missing` | Low | Live, Manifest |
| 78 | `pod-disruption-budget` | Low | Live, Manifest |
| 79 | `topology-spread` | Low | Live, Manifest |
| 80 | `node-affinity-untrusted` | Medium | Live, Manifest |
| 81 | `hpa-without-requests` | Medium | Live, Manifest |

### Storage Security (5 checks)

PVC encryption, reclaim policies, CSI driver security, emptyDir limits,
projected volume security.

| # | Check ID | Default Severity | Modes |
|---|----------|-----------------|-------|
| 82 | `pvc-no-encryption` | Medium | Live, Manifest |
| 83 | `pvc-reclaim-retain` | Medium | Live only |
| 84 | `csi-driver-security` | Low | Live, Manifest |
| 85 | `emptydir-size-limit` | Low | Live, Manifest |
| 86 | `projected-volume-security` | Medium | Live, Manifest |

### Cluster Configuration (10 checks)

Namespace hygiene, LimitRange/ResourceQuota enforcement, API server settings,
etcd encryption, kubelet config. Many of these are live-only since they inspect
cluster state.

| # | Check ID | Default Severity | Modes |
|---|----------|-----------------|-------|
| 87 | `namespace-default-usage` | Medium | Live, Manifest |
| 88 | `limit-range-missing` | Low | Live, Manifest |
| 89 | `resource-quota-missing` | Low | Live, Manifest |
| 90 | `api-server-anonymous` | High | Live only |
| 91 | `audit-logging` | High | Live only |
| 92 | `admission-controllers` | Medium | Live only |
| 93 | `etcd-encryption` | Critical | Live only |
| 94 | `kubelet-config` | High | Live only |
| 95 | `component-versions` | Medium | Live only |
| 96 | `deprecated-api-usage` | Medium | Live, Manifest |

### Supply Chain & Lifecycle (6 checks)

Container runtime socket exposure, health probes, lifecycle hooks, image
freshness, ephemeral container security.

| # | Check ID | Default Severity | Modes |
|---|----------|-----------------|-------|
| 97 | `container-runtime-socket` | Critical | Live, Manifest |
| 98 | `liveness-readiness-probes` | Low | Live, Manifest |
| 99 | `startup-probes` | Info | Live, Manifest |
| 100 | `lifecycle-hooks` | Low | Live, Manifest |
| 101 | `image-age` | Low | Live, Manifest |
| 102 | `ephemeral-container-policy` | Medium | Live, Manifest |

### Cloud Provider (4 checks)

EKS IMDS access, GKE metadata concealment, AKS pod identity, cloud provider
auto-detection. All live-only — require real cloud provider node labels.

| # | Check ID | Default Severity | Modes |
|---|----------|-----------------|-------|
| 103 | `eks-imds-access` | High | Live only |
| 104 | `gke-metadata-concealment` | High | Live only |
| 105 | `aks-pod-identity` | Medium | Live only |
| 106 | `cloud-provider-detection` | Info | Live only |

### CRD Security (4 checks)

CRD validation schemas, conversion webhooks, cert-manager certificate expiry
and insecure key algorithms.

| # | Check ID | Default Severity | Modes |
|---|----------|-----------------|-------|
| 107 | `crd-validation-missing` | Medium | Live, Manifest |
| 108 | `crd-conversion-webhook` | High | Live, Manifest |
| 109 | `cert-manager-expiry` | High | Live only |
| 110 | `cert-manager-insecure` | Medium | Live, Manifest |

---

## Compliance Framework Mapping

Every finding is mapped to one or more industry compliance frameworks:

| Framework | Version | Description |
|-----------|---------|-------------|
| CIS Kubernetes Benchmark | v1.8 | Industry-standard Kubernetes hardening controls |
| MITRE ATT&CK for Containers | v14 | Attacker tactics and techniques mapping |
| NSA/CISA Kubernetes Hardening Guide | v1.2 | US government hardening guidance |

Framework IDs appear in JSON output under each finding's `frameworks` field
and can be used for compliance reporting. Use `--framework` to filter reports
to a specific framework:

```bash
kubevigil scan --framework cis
kubevigil scan --framework mitre -o sarif > mitre-findings.sarif
```

---

## Output Formats

| Format | Flag | Use Case |
|--------|------|----------|
| Text | `-o text` | Human-readable colored terminal output (default) |
| JSON | `-o json` | Machine-readable structured output, CI pipelines |
| Markdown | `-o markdown` | PRs, wikis, documentation |
| SARIF 2.1.0 | `-o sarif` | GitHub Security tab, Azure DevOps, VS Code |
| YAML | `-o yaml` | Kubernetes-native tooling |
| HTML | `-o html` | Self-contained report with inline CSS |
| JUnit XML | `-o junit` | CI systems (Jenkins, GitLab, etc.) |
| CSV | `-o csv` | Spreadsheet analysis, data pipelines |

You can also write directly to a file — the format is inferred from the
extension:

```bash
kubevigil scan -o report.html      # Writes HTML to report.html
kubevigil scan -o findings.sarif   # Writes SARIF to findings.sarif
kubevigil scan -o results.csv      # Writes CSV to results.csv
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Clean scan — no findings at or above the `--fail-on` threshold |
| 1 | Findings exist at or above the `--fail-on` severity |
| 2 | Scan error (bad file path, cluster unreachable, API timeout, etc.) |
| 3 | Configuration error (invalid `.kubevigil.yaml`) |

Use `--fail-on` to control the threshold:

```bash
# Fail only on Critical findings (exit 1 if any Critical found)
kubevigil scan --fail-on critical

# Fail on High or above (default behavior)
kubevigil scan --fail-on high
```

---

## Configuration

Create a `.kubevigil.yaml` in your project root
(see [`configs/kubevigil.example.yaml`](configs/kubevigil.example.yaml)):

```yaml
# KubeVigil Configuration
version: "1"

settings:
  severity_threshold: info   # Minimum severity to include in reports
  fail_on: high              # Minimum severity that causes exit code 1
  concurrency: 10            # Maximum number of checks to run in parallel
  timeout: 5m                # Maximum scan duration

checks:
  disabled: []               # List of check IDs to skip
  #  - runtime-class
  #  - image-age
  overrides: {}              # Per-check severity overrides
  #  privileged:
  #    severity: high

exemptions: []               # Namespace-level exemptions
  #- namespace: kube-system
  #  reason: "System namespace"
  #  approved_by: "platform-team"
```

### Annotation-Based Exemptions

Add the `kubevigil.io/skip` annotation to skip checks on specific resources:

```yaml
metadata:
  annotations:
    kubevigil.io/skip: "*"                    # Skip all checks
    kubevigil.io/skip: "privileged,host-pid"  # Skip specific checks
```

---

## CLI Reference

```
kubevigil scan [flags]

Scan Modes:
  -f, --file string                 Path to YAML file or directory (manifest mode)
      --kubeconfig string           Path to kubeconfig file (live mode)
      --context string              Kubeconfig context to use (live mode)

Scope:
  -n, --namespace string            Scan only this namespace
      --exclude-namespace string    Exclude this namespace
      --exclude-infra               Exclude infrastructure namespaces
                                    (monitoring, rook-ceph, calico, etc.)
      --include-system-namespaces   Include kube-system, kube-public,
                                    kube-node-lease (excluded by default)
      --include-managed             Include managed Pods and ReplicaSets
                                    (filtered by default to avoid duplicates)

Filtering:
      --severity string             Minimum severity to report
                                    (info, low, medium, high, critical)
      --fail-on string              Minimum severity for exit code 1
      --framework string            Filter by compliance framework
                                    (cis, mitre, nsa)

Output:
  -o, --output string               Output format or file path
                                    (text, json, markdown, yaml, html,
                                    sarif, junit, csv; or report.html, etc.)
                                    Default: text
      --no-aggregate                Show every finding individually instead
                                    of grouping by check
      --summary-only                Show only the summary table (text only)
      --no-color                    Disable colored output

Performance:
      --concurrency int             Max concurrent checks (overrides config)

General:
      --config string               Config file path (default: auto-discover)
  -v, --verbose                     Enable verbose logging
  -h, --help                        Help
```

Other commands:

```
kubevigil list checks       # List all 110 checks with categories and modes
kubevigil version           # Print version, commit, and build date
kubevigil completion        # Generate shell completion (bash, zsh, fish, powershell)
```

---

## Comparison with Other Tools

KubeVigil occupies the same space as Trivy (Aqua), Kubescape (ARMO/CNCF),
Polaris (Fairwinds), and kube-bench (Aqua). Here is how they differ:

| Capability | KubeVigil | Trivy | Kubescape | Polaris | kube-bench |
|------------|-----------|-------|-----------|---------|------------|
| Security checks | 110 | ~150 misconfig rules | 48 controls | ~30 checks | ~100 CIS checks |
| Scan mode | Live + Manifest | Live + Manifest + Image + IaC | Live + Manifest | Live + Manifest | Node-level (in-cluster Job) |
| Vulnerability scanning | — | ✓ (images, OS, libs) | ✓ (image scanning) | — | — |
| CIS Benchmark | Framework mapping | Framework mapping | Framework mapping | — | Native CIS runner |
| MITRE ATT&CK mapping | ✓ | — | ✓ | — | — |
| NSA/CISA mapping | ✓ | — | ✓ | — | — |
| Output formats | 8 (incl. SARIF) | 20+ | JSON, PDF | JSON, YAML, Score | JSON |
| Remediation guides | Per-finding with YAML | Per-finding | Per-control | Per-check | Manual |
| Annotation exemptions | ✓ | ✓ | ✓ | ✓ | — |
| Single binary | ✓ | ✓ | ✓ | ✓ | Container image |
| RBAC analysis | 15 checks | Basic | Basic | — | — |
| Secrets analysis | 7 checks (entropy) | — | Basic | — | — |

KubeVigil focuses on breadth of Kubernetes-native misconfiguration detection
with strong compliance mapping and actionable remediation. It does not do
container image vulnerability scanning — pair it with Trivy or Grype for that.

---

## Testing

KubeVigil has comprehensive test coverage across multiple layers:

```bash
make test          # Unit tests with race detection (all packages)
make test-cover    # Generate coverage report
make lint          # Run golangci-lint
make check         # All quality gates: vet + lint + test
```

### E2E Test Suite

A full end-to-end test suite validates all 110 checks against real Kubernetes
manifests and live Kind clusters. The suite includes 11 scenario categories,
3 cluster topologies (single-node, multi-node, HA), and cross-validation
against Trivy, Kubescape, Polaris, and kube-bench.

See [`test/e2e/README.md`](test/e2e/README.md) for setup instructions and
[`test/e2e/E2E-TEST-REPORT.md`](test/e2e/E2E-TEST-REPORT.md) for detailed
validation results.

---

## Roadmap

- [x] **Phase 1** — Core engine, 25 workload checks, text/JSON output, CLI,
  configuration
- [x] **Phase 2** — 85 additional checks (110 total), 6 new output formats,
  CIS/MITRE/NSA framework mapping
- [ ] **Phase 3** — Auto-remediation (`kubevigil fix`)
- [ ] **Phase 4** — GitHub Action, baseline management, PR decoration
- [ ] **Phase 5** — Admission webhooks, operator mode, Prometheus metrics
- [ ] **Phase 6** — Multi-cluster, trend analysis, Rego policies
- [ ] **Phase 7** — SDK, plugin system, Helm/Krew/Homebrew distribution

---

## Development

```bash
make build         # Build binary to ./bin/kubevigil
make test          # Run all tests with race detection
make test-cover    # Generate coverage report
make lint          # Run golangci-lint
make vet           # Run go vet
make fmt           # Format code (gofmt + goimports)
make check         # All quality gates (vet + lint + test)
make clean         # Remove build artifacts
```

### Project Structure

```
cmd/kubevigil/          # CLI entrypoint (Cobra commands)
internal/
  checker/              # All 110 security checks (one file per check)
  config/               # Configuration loading and validation
  engine/               # Scan orchestration, parallel execution
  frameworks/           # CIS, MITRE, NSA mapping tables
  k8s/                  # Kubernetes client, resource discovery
  report/               # Output formatters (text, json, html, sarif, etc.)
  version/              # Build version injection
configs/                # Example configuration file
test/
  e2e/                  # End-to-end tests (scenarios, clusters, scripts)
  fixtures/             # Test fixture data
  golden/               # Golden file tests for output formats
  helpers/              # Shared test utilities
  integration/          # Integration tests
```

---

## License

Apache 2.0 — See [LICENSE](LICENSE) for details.
