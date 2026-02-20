# Security Checks Overview

KubeVigil includes 110 security checks across 12 categories that inspect your Kubernetes resources for misconfigurations, excessive permissions, and policy violations. Each check runs in live mode (against a running cluster) or manifest mode (against YAML files), or both.

## Categories

| Category | Checks | Description | Details |
|----------|--------|-------------|---------|
| Workload Security | 25 | Container and pod security context, host isolation, resource management | [workload.md](workload.md) |
| Image Security | 9 | Image tagging, digest pinning, registry policies, supply chain | [image.md](image.md) |
| Identity & Access (RBAC) | 15 | Service accounts, token management, role permissions, bindings | [rbac.md](rbac.md) |
| Secrets Management | 7 | Secret storage, rotation, encryption, external secrets | [secrets.md](secrets.md) |
| Network Security | 12 | NetworkPolicies, Ingress TLS, service exposure, DNS, service mesh | [network.md](network.md) |
| Pod Security Standards | 6 | PSA labels, Baseline/Restricted compliance, PSP migration | [psa.md](psa.md) |
| Scheduling & Availability | 8 | Tolerations, PriorityClass, PDB, topology spread, HPA | [scheduling.md](scheduling.md) |
| Storage Security | 5 | PVC encryption, reclaim policies, CSI drivers, emptyDir limits | [storage.md](storage.md) |
| Cluster Configuration | 10 | API server, etcd encryption, kubelet, admission controllers | [cluster.md](cluster.md) |
| Supply Chain & Lifecycle | 5 | Runtime sockets, health probes, image age, lifecycle hooks | [supply-chain.md](supply-chain.md) |
| Cloud Provider | 4 | EKS IMDS, GKE metadata, AKS pod identity (all live-only) | [cloud.md](cloud.md) |
| CRD Security | 4 | CRD validation, conversion webhooks, cert-manager | [crd.md](crd.md) |

## How Checks Work

Each check inspects specific fields on Kubernetes resources. For example, the `privileged` check reads `securityContext.privileged` on every container in every workload (Deployments, StatefulSets, DaemonSets, Jobs, CronJobs, and bare Pods). When a check finds a misconfiguration, it produces a **finding** that includes:

- **Check ID** -- a stable kebab-case identifier (e.g., `privileged`, `host-pid`)
- **Severity** -- Critical, High, Medium, Low, or Info
- **Resource** -- the name, namespace, kind, and (optionally) container affected
- **Remediation** -- step-by-step guidance with YAML examples
- **Framework mappings** -- CIS Kubernetes Benchmark, MITRE ATT&CK, and NSA/CISA references

## Severity Distribution

| Severity | Description | Example |
|----------|-------------|---------|
| **Critical** | Direct path to cluster compromise | `privileged`, `host-pid`, `rbac-wildcard-verbs` |
| **High** | Significant security risk | `privilege-escalation`, `host-ports`, `rbac-secret-access` |
| **Medium** | Defense-in-depth gap or hardening miss | `capabilities-not-dropped`, `read-only-rootfs`, `seccomp-profile` |
| **Low** | Best practice recommendation | `run-as-high-uid`, `image-no-digest`, `ingress-class-missing` |
| **Info** | Informational, no immediate risk | `rbac-unused-roles`, `psp-still-present` |

## Auto-Fixable Checks

20 of the 110 checks support automatic remediation via `kubevigil fix`. Each auto-fixable check has a safety classification that determines when it can be applied:

| Classification | Count | Applied with | Risk |
|----------------|-------|-------------|------|
| **Safe** | 7 | `--apply` | Zero risk for standard workloads |
| **Likely Safe** | 9 | `--apply --risk-level moderate` | Very low risk, may affect edge cases |
| **Potentially Breaking** | 4 | `--apply --risk-level aggressive` | Could break functionality |

**Safe (7):** `privileged`, `privilege-escalation`, `automount-token`, `host-pid`, `host-ipc`, `proc-mount`, `share-process-namespace`

**Likely Safe (9):** `capabilities-added`, `capabilities-not-dropped`, `run-as-root`, `read-only-rootfs`, `host-network`, `seccomp-profile`, `image-pull-policy`, `psa-labels-missing`, `psa-mode-audit-only`

**Potentially Breaking (4):** `resource-limits-missing`, `resource-requests-missing`, `ephemeral-storage-limits`, `host-ports`

The remaining 90 checks provide remediation guidance but require manual intervention. See [Auto-Fix Risk Levels](../auto-fix/risk-levels.md) for details on the fix safety model.

## Scan Modes

| Mode | Flag | Description |
|------|------|-------------|
| **Live** | `kubevigil scan` | Scans a running cluster via the Kubernetes API |
| **Manifest** | `kubevigil scan -f path/` | Scans YAML files without cluster access |

Most checks support both modes. A few checks are mode-specific:

- **Live only:** `secrets-unencrypted` (requires cluster introspection), `secrets-stale` (requires timestamps), `external-secrets-sync` (requires CRD status)
- **Manifest only:** `secrets-hardcoded-manifests` (targets source YAML files)

## Compliance Framework Mappings

Every check maps to one or more compliance framework controls:

- **CIS Kubernetes Benchmark v1.8** -- Center for Internet Security hardening guide
- **MITRE ATT&CK for Containers v14** -- Threat-based attack technique mapping
- **NSA/CISA Kubernetes Hardening Guide v1.2** -- US government security recommendations

Use `kubevigil scan --output sarif` for SARIF output with embedded framework references, or `kubevigil scan --output html` for a visual compliance dashboard.
