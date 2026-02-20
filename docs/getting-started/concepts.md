# Key Concepts

This page explains the core concepts you encounter when using KubeVigil.

## Checks

A **check** is a single security rule that KubeVigil evaluates against Kubernetes resources. Each check has:

- **ID** -- a unique string identifier (e.g., `privileged`, `host-network`, `wildcard-verb`)
- **Severity** -- how serious a violation is (Critical, High, Medium, Low, Info)
- **Categories** -- which security domain it belongs to
- **Supported scan modes** -- whether it works in live mode, manifest mode, or both
- **Remediation** -- a description of the issue and a ready-to-use YAML fix

KubeVigil ships with **110 security checks**. List them all with:

```bash
kubevigil list checks
```

## Categories

Checks are organized into 12 categories:

| Category | Checks | What it covers |
|----------|--------|----------------|
| Workload | 25 | Container and pod security context, privilege escalation, capabilities |
| Image | 9 | Tag pinning, allowed/blocked registries, pull policies |
| RBAC | 15 | Roles, ClusterRoles, wildcards, privilege escalation bindings |
| Secrets | 7 | Secrets management, environment variable exposure, entropy detection |
| Network | 12 | NetworkPolicy coverage, host networking, exposed services |
| Pod Security Standards | 6 | PSA baseline and restricted profile violations |
| Scheduling | 8 | Tolerations, node affinity, priority classes, spread constraints |
| Storage | 5 | HostPath mounts, persistent volume access modes, ephemeral storage |
| Cluster Configuration | 10 | API server settings, admission controllers, audit logging |
| Supply Chain | 5 | Container runtime sockets, health probes, image age, lifecycle hooks |
| Cloud Provider | 4 | AWS, GCP, Azure-specific misconfigurations |
| CRD | 4 | Custom resource validation, conversion webhooks |

## Severity Levels

Every finding carries one of five severity levels:

| Severity | Meaning |
|----------|---------|
| **Critical** | Direct path to cluster compromise. Fix immediately. |
| **High** | Significant security weakness that attackers can exploit. |
| **Medium** | Defense-in-depth gap. Not directly exploitable alone. |
| **Low** | Best practice deviation with minimal direct risk. |
| **Info** | Informational observation. No direct security impact. |

Filter findings by severity with `--severity`:

```bash
# Show only Critical and High
kubevigil scan -f ./manifests/ --severity high
```

## Scan Modes

KubeVigil operates in two modes:

**Live mode** connects to the Kubernetes API through your kubeconfig and inspects running resources:

```bash
kubevigil scan
```

**Manifest mode** parses YAML files from disk. No cluster connection needed:

```bash
kubevigil scan -f ./manifests/
```

Of the 110 checks, 94 work in both modes, 15 are live-only (they inspect runtime cluster state that does not exist in static YAML), and 1 is manifest-only.

## Findings

A **finding** is a single security issue detected on a specific resource. When KubeVigil scans, it produces a list of findings. Each finding contains:

- **Check ID** -- which check flagged this issue
- **Severity** -- the severity level of the finding
- **Resource** -- the kind, name, and namespace of the affected resource
- **Field path** -- the specific YAML field involved (e.g., `spec.containers[0].securityContext.privileged`)
- **Message** -- a human-readable description of the issue
- **Remediation** -- what to do about it, with a YAML snippet
- **Framework mappings** -- which compliance controls this finding maps to

## Posture Score

KubeVigil computes a **posture score** from 0 to 100 based on the findings. A higher score means fewer and less severe findings. The score appears in the text output summary and in the HTML report.

| Grade | Score range |
|-------|------------|
| A | 80-100 |
| B | 60-79 |
| C | 40-59 |
| D | 20-39 |
| F | 0-19 |

## Framework Mappings

Every finding is mapped to controls in three industry compliance frameworks:

- **CIS Kubernetes Benchmark v1.8** -- Center for Internet Security best practices for Kubernetes hardening
- **MITRE ATT&CK for Containers v14** -- Adversary tactics and techniques specific to container environments
- **NSA/CISA Kubernetes Hardening Guide v1.2** -- U.S. government guidance for securing Kubernetes

Filter your scan results to a specific framework:

```bash
kubevigil scan -f ./manifests/ --framework cis
```

## Exemptions

You can skip checks on specific resources in two ways:

**Config file exemptions** -- add entries to `.kubevigil.yaml`:

```yaml
exemptions:
  - check: host-network
    resource: kube-system/DaemonSet/kube-proxy
    reason: "kube-proxy requires host networking by design"
```

**Annotation-based exemptions** -- annotate the resource directly:

```yaml
metadata:
  annotations:
    kubevigil.io/skip: "privileged,host-network"
```

Both approaches cause KubeVigil to silently skip the listed checks for that resource.

## Auto-Fix

The `kubevigil fix` command scans manifests, identifies fixable findings, and generates patched YAML. It currently auto-remediates **20 checks** covering container security context, capabilities, service account tokens, and Pod Security Standards.

Key safety properties:

- **Dry-run by default.** Running `kubevigil fix ./manifests/` shows a diff but changes nothing.
- **Risk-tiered application.** `--apply` applies only zero-risk (safe) fixes. `--risk-level moderate` adds likely-safe fixes. `--risk-level aggressive` adds potentially-breaking fixes.
- **Comment-preserving patches.** The YAML round-trip engine preserves comments, key ordering, and formatting.
- **Mandatory backups.** Every `--apply` creates a backup directory with restore instructions.
- **System namespace protection.** Resources in `kube-system`, `kube-public`, and `kube-node-lease` are never auto-fixed unless you pass `--i-understand-system-namespaces`.

See the [Quickstart](quickstart.md) for fix command examples.
