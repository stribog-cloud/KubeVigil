# Live Cluster Scanning

KubeVigil connects to a running Kubernetes cluster through the Kubernetes API to perform a comprehensive security posture assessment. Live scanning discovers all workloads and cluster-level resources, then runs 150 security checks against them.

## Prerequisites

- **kubectl access**: KubeVigil uses your existing kubeconfig to authenticate with the cluster. Any context that works with `kubectl get pods` will work with KubeVigil.
- **RBAC permissions**: Read-only access to all resources in the cluster. KubeVigil never modifies cluster state. The following resource types are queried:
  - Deployments, DaemonSets, StatefulSets, Jobs, CronJobs
  - Pods, ReplicaSets
  - Services, Ingresses
  - NetworkPolicies
  - Roles, ClusterRoles, RoleBindings, ClusterRoleBindings
  - ConfigMaps, Secrets
  - Namespaces, Nodes
  - PersistentVolumeClaims, PersistentVolumes
  - CSIDrivers, CustomResourceDefinitions (CRDs)

A ClusterRole with `get`, `list`, and `watch` permissions on these resources is sufficient.

## Basic Usage

Scan the current cluster using your default kubeconfig context:

```bash
kubevigil scan
```

This connects to the cluster, discovers all resources across all non-system namespaces, runs all applicable checks, and prints a text summary to stdout.

## Kubeconfig and Context

Use `--kubeconfig` to specify an alternate kubeconfig file, and `--context` to select a specific context within it:

```bash
# Use a specific kubeconfig file
kubevigil scan --kubeconfig /path/to/kubeconfig

# Use a specific context from the default kubeconfig
kubevigil scan --context staging-cluster

# Both together
kubevigil scan --kubeconfig /path/to/kubeconfig --context production
```

If neither flag is set, KubeVigil uses the standard kubeconfig resolution: the `KUBECONFIG` environment variable, then `~/.kube/config`.

## Namespace Filtering

By default, KubeVigil scans all non-system namespaces. System namespaces (`kube-system`, `kube-public`, `kube-node-lease`) are excluded unless explicitly included.

### Scan a single namespace

```bash
kubevigil scan -n my-app
```

### Exclude a specific namespace

```bash
kubevigil scan --exclude-namespace staging
```

### Include system namespaces

```bash
kubevigil scan --include-system-namespaces
```

This adds `kube-system`, `kube-public`, and `kube-node-lease` to the scan scope.

### Exclude infrastructure namespaces

```bash
kubevigil scan --exclude-infra
```

This excludes common infrastructure namespaces such as `monitoring`, `rook-ceph`, `calico-system`, and similar. The list can be extended via the `.kubevigil.yaml` configuration file.

## Including Managed Resources

By default, KubeVigil filters out Pods and ReplicaSets that are owned by higher-level controllers (Deployments, StatefulSets, DaemonSets). This avoids duplicate findings -- a Deployment and its Pods share the same PodSpec, so reporting both would double-count issues.

To include these managed resources:

```bash
kubevigil scan --include-managed
```

This is useful when you want to verify that the actual running Pods match the expected configuration, or when debugging controller behavior.

## Live-Only Checks

15 checks require live cluster state and only run in live mode. These checks cannot be performed against static YAML manifests because they depend on runtime cluster configuration, API server settings, or dynamic resource state:

| Check ID | Description |
|----------|-------------|
| `api-server-anonymous` | Detects anonymous API server access |
| `audit-logging` | Verifies audit logging is enabled |
| `admission-controllers` | Checks for required admission controllers |
| `etcd-encryption` | Verifies etcd encryption at rest |
| `kubelet-config` | Audits kubelet configuration settings |
| `component-versions` | Checks Kubernetes component versions |
| `secrets-unencrypted` | Detects unencrypted Secrets at rest |
| `secrets-stale` | Identifies Secrets that have not been rotated |
| `external-secrets-sync` | Verifies external secrets synchronization status |
| `eks-imds-access` | Checks EKS IMDS access controls |
| `gke-metadata-concealment` | Verifies GKE metadata concealment |
| `aks-pod-identity` | Checks AKS pod identity configuration |
| `cloud-provider-detection` | Detects cloud provider and checks provider-specific settings |
| `pvc-reclaim-retain` | Checks PVC reclaim policy is set to Retain |
| `cert-manager-expiry` | Monitors certificate expiry through cert-manager |

## Concurrency

KubeVigil runs checks in parallel for performance. The default concurrency is controlled by the configuration file (default: 10 parallel checks). Override it with `--concurrency`:

```bash
# Run up to 20 checks in parallel
kubevigil scan --concurrency 20

# Run checks sequentially (useful for debugging)
kubevigil scan --concurrency 1
```

## Framework Filtering

Filter findings by compliance framework to focus on specific standards:

```bash
# Only CIS Kubernetes Benchmark v1.8 findings
kubevigil scan --framework cis

# Only MITRE ATT&CK v14 findings
kubevigil scan --framework mitre

# Only NSA/CISA Hardening Guide v1.2 findings
kubevigil scan --framework nsa
```

## Severity Filtering

Control which findings are reported and which trigger a non-zero exit code:

```bash
# Only report high and critical findings
kubevigil scan --severity high

# Report all findings, but only exit 1 for critical
kubevigil scan --fail-on critical

# Combine: show medium+ findings, fail on high+
kubevigil scan --severity medium --fail-on high
```

Valid severity levels: `info`, `low`, `medium`, `high`, `critical`.

## Output Formats

Live scan results can be written in any of the 8 supported formats. See [Output Formats](output-formats.md) for details.

```bash
# JSON to stdout
kubevigil scan -o json

# HTML report to file
kubevigil scan -o report.html

# SARIF for GitHub Security tab
kubevigil scan -o results.sarif
```

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed, no findings above the `--fail-on` threshold |
| `1` | Findings detected above the `--fail-on` threshold |
| `2` | Scan error (connection failure, timeout, etc.) |
| `3` | Configuration error (invalid flags, malformed config file) |

## Configuration

All scan flags can also be set in `.kubevigil.yaml`. CLI flags override configuration file values. See [Configuration](../configuration/) for the full reference.

```yaml
# .kubevigil.yaml
settings:
  severity_threshold: medium
  fail_on: high
  concurrency: 15
  include_managed: false
  include_system_namespaces: false
  exclude_infra: true
```
