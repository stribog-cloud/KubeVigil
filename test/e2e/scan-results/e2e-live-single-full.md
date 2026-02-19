# KubeVigil Scan Report

## Executive Summary

**Posture Score: 43/100**

| Metric | Value |
|--------|-------|
| KubeVigil | 82c45af |
| Scan Mode | Live |
| Duration | 4.82s |
| Total Findings | 2115 |
| Resources Affected | 141 |
| Namespaces | 19 |
| Checks Run | 103 |
| Checks with Findings | 80 |
| Checks Clean | 23 |
| Checks Skipped | 7 |
| Checks Errored | 0 |
| Pass Rate | 22% |

<details>
<summary><b>Findings by Check (80)</b></summary>

| Severity | Check | Findings | Resources |
|----------|-------|----------|-----------|
| 🔴 Critical | rbac-wildcard-apigroups | 8 | 8 |
| 🔴 Critical | rbac-wildcard-resources | 7 | 7 |
| 🔴 Critical | host-path-volumes | 6 | 6 |
| 🔴 Critical | rbac-escalation-verbs | 5 | 5 |
| 🔴 Critical | rbac-cluster-admin | 3 | 3 |
| 🔴 Critical | rbac-wildcard-verbs | 3 | 3 |
| 🔴 Critical | host-network | 2 | 2 |
| 🔴 Critical | host-pid | 2 | 2 |
| 🔴 Critical | privileged | 2 | 2 |
| 🔴 Critical | container-runtime-socket | 1 | 1 |
| 🔴 Critical | host-ipc | 1 | 1 |
| 🔴 Critical | secrets-unencrypted | 1 | 1 |
| 🟠 High | privilege-escalation | 89 | 68 |
| 🟠 High | run-as-root | 83 | 64 |
| 🟠 High | automount-token | 69 | 69 |
| 🟠 High | default-service-account | 66 | 66 |
| 🟠 High | network-policy-missing | 15 | 15 |
| 🟠 High | psa-baseline-violations | 9 | 8 |
| 🟠 High | rbac-secret-access | 7 | 7 |
| 🟠 High | network-policy-default-deny | 6 | 3 |
| 🟠 High | secrets-in-configmap | 6 | 2 |
| 🟠 High | rbac-group-bindings | 5 | 5 |
| 🟠 High | capabilities-added | 4 | 3 |
| 🟠 High | rbac-exec-access | 4 | 4 |
| 🟠 High | toleration-control-plane | 4 | 2 |
| 🟠 High | ingress-no-tls | 3 | 3 |
| 🟠 High | host-ports | 2 | 2 |
| 🟠 High | external-ips | 1 | 1 |
| 🟠 High | priority-class-system | 1 | 1 |
| 🟠 High | proc-mount | 1 | 1 |
| 🟠 High | unsafe-sysctls | 1 | 1 |
| 🟡 Medium | psa-restricted-violations | 261 | 68 |
| 🟡 Medium | apparmor-profile | 90 | 69 |
| 🟡 Medium | capabilities-not-dropped | 89 | 68 |
| 🟡 Medium | run-as-group | 88 | 67 |
| 🟡 Medium | seccomp-profile | 88 | 68 |
| 🟡 Medium | read-only-rootfs | 87 | 66 |
| 🟡 Medium | resource-requests-missing | 82 | 63 |
| 🟡 Medium | image-pull-policy | 77 | 64 |
| 🟡 Medium | resource-limits-missing | 65 | 57 |
| 🟡 Medium | token-projection-config | 45 | 45 |
| 🟡 Medium | projected-volume-security | 25 | 24 |
| 🟡 Medium | psa-labels-missing | 18 | 18 |
| 🟡 Medium | network-policy-egress-unrestricted | 16 | 16 |
| 🟡 Medium | image-tag-latest | 8 | 6 |
| 🟡 Medium | secrets-in-env | 8 | 3 |
| 🟡 Medium | rbac-log-access | 6 | 6 |
| 🟡 Medium | network-policy-overly-permissive | 3 | 3 |
| 🟡 Medium | psa-mode-audit-only | 3 | 3 |
| 🟡 Medium | pvc-no-encryption | 3 | 3 |
| 🟡 Medium | image-tag-missing | 2 | 2 |
| 🟡 Medium | ingress-wildcard-host | 2 | 2 |
| 🟡 Medium | namespace-default-usage | 2 | 2 |
| 🟡 Medium | node-affinity-untrusted | 2 | 2 |
| 🟡 Medium | cloud-iam-binding | 1 | 1 |
| 🟡 Medium | hpa-without-requests | 1 | 1 |
| 🟡 Medium | selinux-options | 1 | 1 |
| 🟡 Medium | service-type-loadbalancer | 1 | 1 |
| 🟡 Medium | service-type-nodeport | 1 | 1 |
| 🟡 Medium | share-process-namespace | 1 | 1 |
| 🟡 Medium | toleration-all | 1 | 1 |
| 🔵 Low | liveness-readiness-probes | 173 | 69 |
| 🔵 Low | ephemeral-storage-limits | 90 | 69 |
| 🔵 Low | image-no-digest | 90 | 69 |
| 🔵 Low | runtime-class | 69 | 69 |
| 🔵 Low | topology-spread | 69 | 69 |
| 🔵 Low | priority-class-missing | 68 | 68 |
| 🔵 Low | limit-range-missing | 18 | 18 |
| 🔵 Low | resource-quota-missing | 18 | 18 |
| 🔵 Low | pod-disruption-budget | 6 | 6 |
| 🔵 Low | ingress-class-missing | 3 | 3 |
| 🔵 Low | psa-version-pinning | 3 | 1 |
| 🔵 Low | secrets-default-type | 3 | 3 |
| 🔵 Low | emptydir-size-limit | 2 | 2 |
| 🔵 Low | lifecycle-hooks | 2 | 2 |
| 🔵 Low | run-as-high-uid | 2 | 2 |
| 🔵 Low | rbac-subject-external | 1 | 1 |
| 🔵 Low | resource-limits-ratio | 1 | 1 |
| ⬜ Info | rbac-unused-roles | 2 | 2 |
| ⬜ Info | startup-probes | 1 | 1 |

</details>

## Findings (2115 total)

| Severity | Count |
|----------|-------|
| 🔴 Critical | 38 |
| 🟠 High | 377 |
| 🟡 Medium | 1079 |
| 🔵 Low | 618 |
| ⬜ Info | 3 |

### Checks Passed (23)

<details>
<summary>23 checks ran with zero findings</summary>

- `admission-controllers`
- `aks-pod-identity`
- `api-server-anonymous`
- `audit-logging`
- `cloud-provider-detection`
- `component-versions`
- `crd-conversion-webhook`
- `crd-validation-missing`
- `csi-driver-security`
- `dns-security`
- `eks-imds-access`
- `ephemeral-container-policy`
- `etcd-encryption`
- `gke-metadata-concealment`
- `image-age`
- `image-provenance`
- `image-registry-allowlist`
- `image-registry-blocklist`
- `image-sbom-attestation`
- `image-signature-verification`
- `kubelet-config`
- `pvc-reclaim-retain`
- `secrets-stale`

</details>

## Compliance Summary

### CIS

| Control | Title | Severity | Resources |
|---------|-------|----------|-----------|
| 5.1.1 | Ensure that the cluster-admin role is only used where required | Critical | 23 |
| 5.1.8 | Limit use of the Bind, Impersonate and Escalate permissions in the Kubernetes cluster | Critical | 5 |
| 5.1.3 | Minimize wildcard use in Roles and ClusterRoles | Critical | 11 |
| 1.2.28 | Ensure that the --encryption-provider-config argument is set as appropriate | Critical | 1 |
| 1.2.29 | Ensure that encryption providers are appropriately configured | Critical | 1 |
| 5.2.5 | Minimize the admission of containers wishing to share the host network namespace | Critical | 2 |
| 5.2.3 | Minimize the admission of containers wishing to share the host process ID namespace | Critical | 2 |
| 5.2.2 | Minimize the admission of privileged containers | Critical | 2 |
| 5.2.4 | Minimize the admission of containers wishing to share the host IPC namespace | Critical | 1 |
| 5.2.12 | Minimize the admission of HostPath volumes | Critical | 6 |
| 5.1.2 | Minimize access to secrets | High | 7 |
| 5.1.7 | Avoid use of system:masters group | High | 5 |
| 5.1.6 | Ensure that Service Account Tokens are only mounted where necessary | High | 69 |
| 5.1.5 | Ensure that default service accounts are not actively used | High | 66 |
| 5.2.6 | Minimize the admission of containers with allowPrivilegeEscalation | High | 68 |
| 5.2.7 | Minimize the admission of root containers | High | 67 |
| 5.3.2 | Ensure that all Namespaces have Network Policies defined | High | 27 |
| 5.2.9 | Minimize the admission of containers with added capabilities | High | 3 |
| 5.2.10 | Minimize the admission of containers with capabilities assigned | High | 68 |
| 5.2.13 | Minimize the admission of containers which use HostPorts | High | 2 |
| 5.2.1 | Ensure that the cluster has at least one active policy control mechanism in place | High | 87 |
| 5.6.3 | Apply Security Context to Your Pods and Containers | High | 88 |
| 5.4.1 | Prefer using secrets as files over secrets as environment variables | High | 31 |
| 5.2.8 | Minimize the admission of containers with the NET_RAW capability | Medium | 68 |
| 5.5.1 | Configure Image Provenance using ImagePolicyWebhook admission controller | Medium | 69 |
| 5.6.4 | The default namespace should not be used | Medium | 2 |
| 5.6.2 | Ensure that the seccomp profile is set to docker/default in your pod definitions | Medium | 68 |
| 5.4.2 | Consider external secret storage | Medium | 6 |

### MITRE

| Control | Title | Severity | Resources |
|---------|-------|----------|-----------|
| T1078 | Valid Accounts | Critical | 26 |
| T1068 | Exploitation for Privilege Escalation | Critical | 73 |
| T1552 | Unsecured Credentials | Critical | 39 |
| T1611 | Escape to Host | Critical | 69 |
| T1040 | Network Sniffing | Critical | 5 |
| T1057 | Process Discovery | Critical | 3 |
| T1610 | Deploy Container | Critical | 23 |
| T1006 | Direct Volume Access | Critical | 6 |
| T1609 | Container Administration Command | High | 4 |
| T1552.007 | Unsecured Credentials: Container API | High | 69 |
| T1078.001 | Valid Accounts: Default Accounts | High | 66 |
| T1046 | Network Service Discovery | High | 21 |
| T1071 | Application Layer Protocol | High | 3 |
| T1190 | Exploit Public-Facing Application | High | 6 |
| T1557 | Adversary-in-the-Middle | High | 3 |
| T1499 | Endpoint Denial of Service | High | 88 |
| T1530 | Data from Cloud Storage | Medium | 9 |
| T1525 | Implant Internal Image | Medium | 69 |
| T1565.001 | Stored Data Manipulation | Medium | 66 |
| T1048 | Exfiltration Over Alternative Protocol | Medium | 16 |
| T1078.004 | Valid Accounts: Cloud Accounts | Medium | 1 |
| T1059 | Command and Scripting Interpreter | Low | 2 |

### NSA

| Control | Title | Severity | Resources |
|---------|-------|----------|-----------|
| 3.1 | RBAC policies | Critical | 100 |
| 5.1 | Secrets management | Critical | 39 |
| 5.2 | Encryption at rest | Critical | 4 |
| 1.3 | Minimized host resource access | Critical | 22 |
| 4.1 | Network separation | Critical | 23 |
| 1.1 | Non-root containers | Critical | 68 |
| 2.1 | Pod security enforcement | Critical | 88 |
| 3.2 | Service account management | High | 70 |
| 4.2 | Network policy enforcement | High | 21 |
| 4.3 | TLS encryption | High | 3 |
| 1.5 | Resource requests and limits | High | 88 |
| 1.4 | Trusted container images | Medium | 69 |
| 1.2 | Immutable container filesystems | Medium | 66 |

### Category Breakdown

| Category | Findings | Critical | High | Medium | Low | Info |
|----------|----------|----------|------|--------|-----|------|
| Application | 2070 | 13 | 364 | 1074 | 617 | 2 |
| Cluster-Scoped | 45 | 25 | 13 | 5 | 1 | 1 |

## Application Namespaces

### default (51 findings — 🟠8 🟡27 🔵16)

| Severity | Check | Resources | Message | Frameworks |
|----------|-------|-----------|---------|-----------|
| 🟠 High | automount-token | **2 resources** | Deployment "kv-e2e-default-web" auto-mounts a ServiceAccount token. Most workloads do not need Kubernetes API access. | CIS 5.1.6 · MITRE T1552.007 · NSA 3.2 |
| 🟠 High | default-service-account | **2 resources** | Deployment "kv-e2e-default-web" uses the default ServiceAccount, which may have unintended permissions. | CIS 5.1.5 · CIS 5.1.6 · MITRE T1078.001 · NSA 3.1 · NSA 3.2 |
| 🟠 High | privilege-escalation | **2 resources** | Container "pause" does not set allowPrivilegeEscalation to false, permitting privilege escalation. | CIS 5.2.6 · MITRE T1068 · MITRE T1611 · NSA 1.1 · NSA 2.1 |
| 🟠 High | run-as-root | **2 resources** | Container "pause" does not set runAsNonRoot: true and may run as root. | CIS 5.2.7 · MITRE T1611 · NSA 1.1 |
| 🟡 Medium | psa-labels-missing | default/Namespace/default | Namespace "default" is missing the pod-security.kubernetes.io/enforce label; pod security is not enforced. | CIS 5.2.1 · MITRE T1610 · NSA 2.1 |
| 🟡 Medium | apparmor-profile | **2 resources** | Container "pause" does not have an AppArmor profile set. | CIS 5.6.3 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | capabilities-not-dropped | **2 resources** | Container "pause" does not drop ALL capabilities, leaving it with unnecessary default privileges. | CIS 5.2.8 · CIS 5.2.10 · MITRE T1068 · NSA 1.1 |
| 🟡 Medium | image-pull-policy | **2 resources** | Container "pause" uses a mutable image tag with pullPolicy "IfNotPresent" (image: registry.k8s.io/pause:3.9), risking stale images. | CIS 5.5.1 · MITRE T1525 · NSA 1.4 |
| 🟡 Medium | namespace-default-usage | **2 resources** | Deployment "kv-e2e-default-web" is deployed in the default namespace. | CIS 5.6.4 · MITRE T1078.001 · NSA 3.1 |
| 🟡 Medium | psa-restricted-violations | **6 resources** | Deployment "kv-e2e-default-web" container "pause" violates PSS Restricted: runAsNonRoot is not true. | CIS 5.2.1 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | read-only-rootfs | **2 resources** | Container "pause" does not have a read-only root filesystem. | CIS 5.6.3 · MITRE T1565.001 · NSA 1.2 |
| 🟡 Medium | resource-limits-missing | **2 resources** | Container "pause" is missing both CPU and memory limits. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🟡 Medium | resource-requests-missing | **2 resources** | Container "pause" is missing both CPU and memory requests. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🟡 Medium | run-as-group | **2 resources** | Container "pause" does not set runAsGroup; the process will run as GID 0 (root group) by default. | CIS 5.2.7 · MITRE T1068 · NSA 1.1 |
| 🟡 Medium | seccomp-profile | **2 resources** | Container "pause" does not have a Seccomp profile set at either the container or pod level. | CIS 5.6.2 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | token-projection-config | **2 resources** | Deployment "kv-e2e-default-web" does not use explicitly configured projected ServiceAccount tokens with expiry and audience restrictions. | CIS 5.1.6 · MITRE T1552.007 · NSA 3.2 |
| 🔵 Low | limit-range-missing | default/Namespace/default | Namespace "default" has no LimitRange defined. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | resource-quota-missing | default/Namespace/default | Namespace "default" has no ResourceQuota defined. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | ephemeral-storage-limits | **2 resources** | Container "pause" is missing ephemeral-storage limits. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | image-no-digest | **2 resources** | Container "pause" image is not pinned by digest (image: registry.k8s.io/pause:3.9), allowing tag mutation. | CIS 5.5.1 · MITRE T1525 · NSA 1.4 |
| 🔵 Low | liveness-readiness-probes | **4 resources** | Container "pause" has no liveness probe configured. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | priority-class-missing | **2 resources** | Deployment "kv-e2e-default-web" has no PriorityClass set; it will be evicted first during resource pressure. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | runtime-class | **2 resources** | Pod "kv-e2e-default-web" does not specify a RuntimeClass, using the default (unsandboxed) runtime. | CIS 5.6.3 · MITRE T1611 · NSA 2.1 |
| 🔵 Low | topology-spread | **2 resources** | Deployment "kv-e2e-default-web" has no topology spread constraints; all replicas may be scheduled on the same node. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |

<details>
<summary>automount-token: 2 affected resources</summary>

- `default/Deployment/kv-e2e-default-web`
- `default/Deployment/kv-e2e-default-worker`

</details>

<details>
<summary>default-service-account: 2 affected resources</summary>

- `default/Deployment/kv-e2e-default-web`
- `default/Deployment/kv-e2e-default-worker`

</details>

<details>
<summary>privilege-escalation: 2 affected resources</summary>

- `default/Deployment/kv-e2e-default-web (pause)`
- `default/Deployment/kv-e2e-default-worker (pause)`

</details>

<details>
<summary>run-as-root: 2 affected resources</summary>

- `default/Deployment/kv-e2e-default-web (pause)`
- `default/Deployment/kv-e2e-default-worker (pause)`

</details>

<details>
<summary>apparmor-profile: 2 affected resources</summary>

- `default/Deployment/kv-e2e-default-web (pause)`
- `default/Deployment/kv-e2e-default-worker (pause)`

</details>

<details>
<summary>capabilities-not-dropped: 2 affected resources</summary>

- `default/Deployment/kv-e2e-default-web (pause)`
- `default/Deployment/kv-e2e-default-worker (pause)`

</details>

<details>
<summary>image-pull-policy: 2 affected resources</summary>

- `default/Deployment/kv-e2e-default-web (pause)`
- `default/Deployment/kv-e2e-default-worker (pause)`

</details>

<details>
<summary>namespace-default-usage: 2 affected resources</summary>

- `default/Deployment/kv-e2e-default-web`
- `default/Deployment/kv-e2e-default-worker`

</details>

<details>
<summary>psa-restricted-violations: 6 affected resources</summary>

- `default/Deployment/kv-e2e-default-web (pause)`
- `default/Deployment/kv-e2e-default-web (pause)`
- `default/Deployment/kv-e2e-default-web (pause)`
- `default/Deployment/kv-e2e-default-worker (pause)`
- `default/Deployment/kv-e2e-default-worker (pause)`
- `default/Deployment/kv-e2e-default-worker (pause)`

</details>

<details>
<summary>read-only-rootfs: 2 affected resources</summary>

- `default/Deployment/kv-e2e-default-web (pause)`
- `default/Deployment/kv-e2e-default-worker (pause)`

</details>

<details>
<summary>resource-limits-missing: 2 affected resources</summary>

- `default/Deployment/kv-e2e-default-web (pause)`
- `default/Deployment/kv-e2e-default-worker (pause)`

</details>

<details>
<summary>resource-requests-missing: 2 affected resources</summary>

- `default/Deployment/kv-e2e-default-web (pause)`
- `default/Deployment/kv-e2e-default-worker (pause)`

</details>

<details>
<summary>run-as-group: 2 affected resources</summary>

- `default/Deployment/kv-e2e-default-web (pause)`
- `default/Deployment/kv-e2e-default-worker (pause)`

</details>

<details>
<summary>seccomp-profile: 2 affected resources</summary>

- `default/Deployment/kv-e2e-default-web (pause)`
- `default/Deployment/kv-e2e-default-worker (pause)`

</details>

<details>
<summary>token-projection-config: 2 affected resources</summary>

- `default/Deployment/kv-e2e-default-web`
- `default/Deployment/kv-e2e-default-worker`

</details>

<details>
<summary>ephemeral-storage-limits: 2 affected resources</summary>

- `default/Deployment/kv-e2e-default-web (pause)`
- `default/Deployment/kv-e2e-default-worker (pause)`

</details>

<details>
<summary>image-no-digest: 2 affected resources</summary>

- `default/Deployment/kv-e2e-default-web (pause)`
- `default/Deployment/kv-e2e-default-worker (pause)`

</details>

<details>
<summary>liveness-readiness-probes: 4 affected resources</summary>

- `default/Deployment/kv-e2e-default-web (pause)`
- `default/Deployment/kv-e2e-default-web (pause)`
- `default/Deployment/kv-e2e-default-worker (pause)`
- `default/Deployment/kv-e2e-default-worker (pause)`

</details>

<details>
<summary>priority-class-missing: 2 affected resources</summary>

- `default/Deployment/kv-e2e-default-web`
- `default/Deployment/kv-e2e-default-worker`

</details>

<details>
<summary>runtime-class: 2 affected resources</summary>

- `default/Deployment/kv-e2e-default-web`
- `default/Deployment/kv-e2e-default-worker`

</details>

<details>
<summary>topology-spread: 2 affected resources</summary>

- `default/Deployment/kv-e2e-default-web`
- `default/Deployment/kv-e2e-default-worker`

</details>

<details>
<summary>Remediation: automount-token (2 resources affected)</summary>

## Why This Matters

When a ServiceAccount token is auto-mounted, every container in the pod can call the Kubernetes API. If a container is compromised through a vulnerability or misconfiguration, the attacker gains API access to enumerate resources, read secrets, or escalate privileges.

## How to Fix

Disable auto-mounting at the pod spec level for workloads that do not need API access:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      automountServiceAccountToken: false
      containers:
        - name: app
          image: my-app:latest
```

For workloads that do require API access, use projected tokens with bounded lifetime and audience restrictions instead of the default long-lived token.

## Learn More

Refer to the Kubernetes documentation on configuring service accounts for pods and CIS Kubernetes Benchmark 5.1.6 for auto-mount token guidance.

**Affected resources:** default/Deployment/kv-e2e-default-web, default/Deployment/kv-e2e-default-worker

</details>

<details>
<summary>Remediation: default-service-account (2 resources affected)</summary>

## Why This Matters

The default ServiceAccount is shared by every pod in a namespace. If any pod is compromised, the attacker inherits whatever permissions have been granted to the default account via role bindings, enabling lateral movement across all workloads sharing it.

## How to Fix

Create a dedicated ServiceAccount for each workload and reference it in the pod spec:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-app
  namespace: production
automountServiceAccountToken: false
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      serviceAccountName: my-app
```

Grant only the permissions the workload actually needs via a dedicated Role and RoleBinding.

## Learn More

See the Kubernetes documentation on managing service accounts and CIS Kubernetes Benchmark 5.1.5 for guidance on ensuring default service accounts are not actively used.

**Affected resources:** default/Deployment/kv-e2e-default-web, default/Deployment/kv-e2e-default-worker

</details>

<details>
<summary>Remediation: privilege-escalation (2 resources affected)</summary>

## Why This Matters

By default, Kubernetes allows containers to escalate privileges via setuid/setgid binaries, which let a process gain more permissions than its parent. An attacker can exploit this using setuid binaries already present in the container image (like `su`, `sudo`, or `ping`) to elevate from a low-privilege user to root.

## How to Fix

Explicitly disable privilege escalation in the container's securityContext:

```yaml
securityContext:
  allowPrivilegeEscalation: false
  runAsNonRoot: true
  capabilities:
    drop: ["ALL"]
```

This blocks the use of setuid/setgid binaries and prevents the no_new_privs Linux flag from being cleared. The vast majority of application containers do not need privilege escalation.

## Learn More

This is required by the Pod Security Standards "Restricted" profile and CIS Benchmark 5.2.5. Disabling privilege escalation is one of the most impactful single-line security improvements you can make.

**Affected resources:** default/Deployment/kv-e2e-default-web, default/Deployment/kv-e2e-default-worker

</details>

<details>
<summary>Remediation: run-as-root (2 resources affected)</summary>

## Why This Matters

Without `runAsNonRoot: true`, Kubernetes does not enforce non-root execution and the container may default to running as UID 0 depending on the image's USER directive. If the image defaults to root, the container process gains full privileges, increasing the blast radius of any compromise or container escape.

## How to Fix

Enforce non-root execution in the securityContext:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
```

With `runAsNonRoot: true`, Kubernetes will reject the pod at admission time if the container image attempts to run as root. Setting an explicit `runAsUser` provides an additional guarantee.

## Learn More

This aligns with CIS Benchmark 5.2.6 and the Pod Security Standards "Restricted" profile. The `runAsNonRoot` field acts as a safety net even when images change their default USER.

**Affected resources:** default/Deployment/kv-e2e-default-web, default/Deployment/kv-e2e-default-worker

</details>

<details>
<summary>Remediation: psa-labels-missing (1 resources affected)</summary>

## Why This Matters

Without PSA enforcement labels, any pod configuration is allowed in this namespace, including privileged containers, host namespace access, and root execution. This bypasses Kubernetes' built-in Pod Security Standards and leaves the namespace vulnerable to workloads that could compromise the node.

## How to Fix

Add Pod Security Admission labels to enforce a security profile on all pods in the namespace:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: default
  labels:
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

Start with `baseline` enforcement to block known privilege escalations, then upgrade to `restricted` after verifying all workloads are compliant.

## Learn More

See the Kubernetes Pod Security Admission documentation and CIS Kubernetes Benchmark 5.2. The three-tier approach (enforce, audit, warn) allows gradual adoption of stricter profiles.

**Affected resources:** default/Namespace/default

</details>

<details>
<summary>Remediation: apparmor-profile (2 resources affected)</summary>

## Why This Matters

AppArmor provides mandatory access control (MAC) that restricts which files, network resources, and capabilities a container process can access. Without an AppArmor profile, the container operates without these restrictions, allowing an attacker with code execution to access any file the container user can read and make unrestricted network connections.

## How to Fix

Apply an AppArmor profile in the container's securityContext (Kubernetes 1.30+):

```yaml
securityContext:
  appArmorProfile:
    type: RuntimeDefault
```

The RuntimeDefault profile provides sensible restrictions for most applications. For tighter control, create a custom Localhost profile that only allows the specific file and network access your application needs.

## Learn More

AppArmor is available on Debian/Ubuntu-based nodes. RHEL/CentOS nodes use SELinux instead. Both provide MAC enforcement. Refer to CIS Benchmark 5.7.5 and the Kubernetes AppArmor documentation.

**Affected resources:** default/Deployment/kv-e2e-default-web, default/Deployment/kv-e2e-default-worker

</details>

<details>
<summary>Remediation: capabilities-not-dropped (2 resources affected)</summary>

## Why This Matters

By default, containers receive a set of Linux capabilities including KILL, SETUID, SETGID, and NET_RAW. These defaults are rarely needed by application code and significantly increase the potential damage from a container compromise. Dropping all capabilities follows the principle of least privilege.

## How to Fix

Explicitly drop all capabilities and selectively add back only what your application needs:

```yaml
securityContext:
  capabilities:
    drop: ["ALL"]
    add: ["NET_BIND_SERVICE"]  # Only if needed
```

Most web applications, API servers, and background workers run perfectly with all capabilities dropped. Test your application after making this change to confirm no functionality is lost.

## Learn More

This is required by the Pod Security Standards "Restricted" profile and aligns with CIS Benchmark 5.2.7. Kubernetes best practice is to treat capability grants as exceptions that require explicit justification.

**Affected resources:** default/Deployment/kv-e2e-default-web, default/Deployment/kv-e2e-default-worker

</details>

<details>
<summary>Remediation: image-pull-policy (2 resources affected)</summary>

## Why This Matters

When a mutable image tag is used without `imagePullPolicy: Always`, Kubernetes may serve a cached version of the image from the node. If the tag has been updated in the registry (with a security patch or -- worse -- a compromised layer), the running container will not reflect those changes.

## How to Fix

Set `imagePullPolicy: Always` for any container using a mutable tag:

```yaml
containers:
  - name: app
    image: nginx:1.25.3
    imagePullPolicy: Always   # Forces fresh pull each time
```

Alternatively, pin images by digest (`image@sha256:...`), which makes the pull policy irrelevant because the content is immutable.

## Learn More

See the Kubernetes documentation on image pull policies and CIS Kubernetes Benchmark 5.4.2 for pull policy guidance.

**Affected resources:** default/Deployment/kv-e2e-default-web, default/Deployment/kv-e2e-default-worker

</details>

<details>
<summary>Remediation: namespace-default-usage (2 resources affected)</summary>

## Why This Matters

The default namespace is a shared, unsecured space that lacks resource quotas, network policies, and RBAC boundaries. Workloads deployed here are exposed to cross-tenant access and resource contention, making it trivial for a compromised pod to interact with other services.

## How to Fix

Create a dedicated namespace for your workload and apply security labels:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: my-app
  labels:
    pod-security.kubernetes.io/enforce: restricted
---
# Then update your workload:
apiVersion: apps/v1
kind: Deployment
metadata:
  namespace: my-app    # Move out of default
```

Apply NetworkPolicies and ResourceQuotas to the new namespace for full isolation.

## Learn More

The CIS Kubernetes Benchmark (5.7.4) recommends against using the default namespace. See https://kubernetes.io/docs/concepts/security/multi-tenancy/ for namespace isolation patterns.

**Affected resources:** default/Deployment/kv-e2e-default-web, default/Deployment/kv-e2e-default-worker

</details>

<details>
<summary>Remediation: psa-restricted-violations (6 resources affected)</summary>

## Why This Matters

Running as root inside a container means that any container escape vulnerability immediately grants root access on the host node. Even without an escape, root inside the container can modify sensitive files, install packages, and access capabilities that non-root users cannot.

## How to Fix

Set `runAsNonRoot: true` and specify a non-root user ID in the security context:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
```

Set this at the pod level to apply to all containers. Ensure your container image supports running as a non-root user (many official images do).

## Learn More

See the Pod Security Standards Restricted profile and CIS Kubernetes Benchmark 5.2.6. Running as non-root is a fundamental container security best practice.

**Affected resources:** default/Deployment/kv-e2e-default-web, default/Deployment/kv-e2e-default-web, default/Deployment/kv-e2e-default-web, default/Deployment/kv-e2e-default-worker, default/Deployment/kv-e2e-default-worker, default/Deployment/kv-e2e-default-worker

</details>

<details>
<summary>Remediation: read-only-rootfs (2 resources affected)</summary>

## Why This Matters

A writable root filesystem allows an attacker who gains code execution in your container to modify application binaries, install attack tools, plant backdoors, or persist malware across container restarts. Making the filesystem read-only eliminates an entire class of post-exploitation techniques.

## How to Fix

Enable a read-only root filesystem and mount writable volumes only where needed:

```yaml
securityContext:
  readOnlyRootFilesystem: true
volumeMounts:
  - name: tmp
    mountPath: /tmp
volumes:
  - name: tmp
    emptyDir: {}
```

Common paths that need write access include /tmp, /var/cache, and /var/run. Mount each as an emptyDir or tmpfs volume rather than making the entire filesystem writable.

## Learn More

This aligns with CIS Benchmark 5.2.4 and the defense-in-depth principle. Combined with dropping capabilities and running as non-root, a read-only filesystem forms a strong container hardening baseline.

**Affected resources:** default/Deployment/kv-e2e-default-web, default/Deployment/kv-e2e-default-worker

</details>

<details>
<summary>Remediation: resource-limits-missing (2 resources affected)</summary>

## Why This Matters

Without resource limits, a single container can consume all available CPU and memory on a node, starving other workloads and triggering cascading failures. An attacker who compromises an unlimited container can mount a denial-of-service attack against the entire node with a simple fork bomb or memory allocation loop.

## How to Fix

Set both CPU and memory limits based on your application's actual resource usage:

```yaml
resources:
  limits:
    cpu: 500m
    memory: 256Mi
  requests:
    cpu: 100m
    memory: 128Mi
```

Profile your application under load to determine appropriate values. Set limits to handle peak usage and requests to match steady-state consumption.

## Learn More

Use LimitRange objects to enforce default limits at the namespace level. Resource limits also determine the pod's QoS class: pods with equal requests and limits get Guaranteed QoS and are last to be evicted.

**Affected resources:** default/Deployment/kv-e2e-default-web, default/Deployment/kv-e2e-default-worker

</details>

<details>
<summary>Remediation: resource-requests-missing (2 resources affected)</summary>

## Why This Matters

Resource requests tell the Kubernetes scheduler how much CPU and memory your container needs. Without requests, the scheduler treats the pod as needing zero resources and may pack too many pods onto a single node. This leads to overcommitment, resource contention, throttling, and OOM kills under load.

## How to Fix

Set resource requests based on your application's steady-state usage:

```yaml
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 256Mi
```

Observe your application's actual resource consumption using `kubectl top` or a monitoring tool, then set requests to match the typical steady-state usage.

## Learn More

Resource requests determine the pod's QoS class and scheduling behavior. Pods with requests equal to limits receive Guaranteed QoS. Use Vertical Pod Autoscaler (VPA) to automatically recommend request values.

**Affected resources:** default/Deployment/kv-e2e-default-web, default/Deployment/kv-e2e-default-worker

</details>

<details>
<summary>Remediation: run-as-group (2 resources affected)</summary>

## Why This Matters

Without an explicit runAsGroup, the container process defaults to GID 0 (the root group). Files and sockets owned by the root group become accessible to the container, including potentially sensitive host files if volumes are mounted. This widens the attack surface unnecessarily.

## How to Fix

Set an explicit non-root group in the securityContext:

```yaml
securityContext:
  runAsGroup: 1000
  runAsUser: 1000
  runAsNonRoot: true
```

Ensure the container image's application files and directories are readable by the specified GID. You may need to adjust file ownership in your Dockerfile with `chown`.

## Learn More

This aligns with CIS Benchmark 5.2.6 and the Pod Security Standards "Restricted" profile. Always set runAsUser, runAsGroup, and runAsNonRoot together for comprehensive identity control.

**Affected resources:** default/Deployment/kv-e2e-default-web, default/Deployment/kv-e2e-default-worker

</details>

<details>
<summary>Remediation: seccomp-profile (2 resources affected)</summary>

## Why This Matters

Without a Seccomp profile, containers can invoke any of the 300+ Linux system calls, leaving the entire kernel attack surface exposed. Kernel vulnerabilities in obscure syscalls are a primary vector for container escapes. Seccomp filtering blocks dangerous syscalls that legitimate applications never use.

## How to Fix

Apply a Seccomp profile at the container or pod level:

```yaml
securityContext:
  seccompProfile:
    type: RuntimeDefault
```

The RuntimeDefault profile blocks approximately 50 dangerous syscalls while allowing normal application behavior. For stricter controls, use a custom Localhost profile tailored to your application's needs. Set the profile at the pod level to apply it to all containers.

## Learn More

Seccomp profiles are required by the Pod Security Standards "Restricted" profile and CIS Benchmark 5.7.2. Use tools like `strace` or the Security Profiles Operator to generate custom profiles for your workloads.

**Affected resources:** default/Deployment/kv-e2e-default-web, default/Deployment/kv-e2e-default-worker

</details>

<details>
<summary>Remediation: token-projection-config (2 resources affected)</summary>

## Why This Matters

Without explicit projection configuration, ServiceAccount tokens use Kubernetes defaults: no audience restriction and a long expiration. A stolen token remains valid for an extended period and can be used against any API server endpoint, widening the blast radius of a compromise.

## How to Fix

Add a projected volume with explicit expiration and audience:

```yaml
spec:
  volumes:
    - name: token
      projected:
        sources:
          - serviceAccountToken:
              expirationSeconds: 3600
              audience: my-api
              path: token
  containers:
    - name: app
      volumeMounts:
        - name: token
          mountPath: /var/run/secrets/tokens
          readOnly: true
```

Projected tokens auto-rotate before expiry and are rejected by endpoints outside the specified audience.

## Learn More

See the Kubernetes documentation on projected volumes and service account token volume projection for detailed configuration options.

**Affected resources:** default/Deployment/kv-e2e-default-web, default/Deployment/kv-e2e-default-worker

</details>

<details>
<summary>Remediation: limit-range-missing (1 resources affected)</summary>

## Why This Matters

Without a LimitRange, any container can be created without resource constraints. A single runaway or malicious pod can consume all node CPU and memory, causing denial of service for other workloads on the same node.

## How to Fix

Create a LimitRange in the namespace to set default and maximum resource constraints:

```yaml
apiVersion: v1
kind: LimitRange
metadata:
  name: default-limits
  namespace: my-app
spec:
  limits:
    - type: Container
      default:
        cpu: 500m
        memory: 256Mi
      defaultRequest:
        cpu: 100m
        memory: 128Mi
      max:
        cpu: "2"
        memory: 1Gi
```

Containers that omit resource requests/limits will inherit these defaults automatically.

## Learn More

CIS Kubernetes Benchmark 5.2.1 recommends LimitRanges for resource governance. See https://kubernetes.io/docs/concepts/policy/limit-range/ for configuration details.

**Affected resources:** default/Namespace/default

</details>

<details>
<summary>Remediation: resource-quota-missing (1 resources affected)</summary>

## Why This Matters

Without a ResourceQuota, a single namespace can consume the entire cluster's CPU, memory, and storage. This creates a noisy-neighbor problem where one team's workloads starve others, and makes capacity planning impossible.

## How to Fix

Create a ResourceQuota to cap the namespace's total resource consumption:

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: compute-quota
  namespace: my-app
spec:
  hard:
    requests.cpu: "10"
    requests.memory: 20Gi
    limits.cpu: "20"
    limits.memory: 40Gi
    pods: "50"
    services: "10"
```

Tune quota values based on the namespace's actual workload requirements and cluster capacity.

## Learn More

CIS Kubernetes Benchmark 5.2.2 recommends ResourceQuotas for multi-tenant clusters. See https://kubernetes.io/docs/concepts/policy/resource-quotas/ for quota configuration and enforcement behavior.

**Affected resources:** default/Namespace/default

</details>

<details>
<summary>Remediation: ephemeral-storage-limits (2 resources affected)</summary>

## Why This Matters

Ephemeral storage includes container logs, emptyDir volumes, and the writable container layer. Without limits, a single container can fill the node's root disk, triggering eviction of all pods on that node and potentially causing a cascading failure across your cluster. This is a common denial-of-service vector.

## How to Fix

Set ephemeral-storage limits alongside your CPU and memory limits:

```yaml
resources:
  limits:
    ephemeral-storage: 1Gi
  requests:
    ephemeral-storage: 500Mi
```

Estimate your application's disk usage from logs, temporary files, and cache data. If your application writes large temporary files, consider using a PersistentVolumeClaim instead of ephemeral storage.

## Learn More

The kubelet evicts pods that exceed their ephemeral-storage limit. Use LimitRange to set default ephemeral-storage limits at the namespace level to catch containers that omit this setting.

**Affected resources:** default/Deployment/kv-e2e-default-web, default/Deployment/kv-e2e-default-worker

</details>

<details>
<summary>Remediation: image-no-digest (2 resources affected)</summary>

## Why This Matters

Image tags are mutable pointers -- a registry administrator or attacker can re-push a different image under the same tag. Without a digest, you have no cryptographic guarantee that the image you deploy is the one you tested.

## How to Fix

Pin images by their SHA-256 content digest for a fully immutable reference:

```yaml
containers:
  - name: app
    image: nginx@sha256:a8281ce420348a01ea6e   # Immutable
```

Use `crane digest nginx:1.25.3` or `skopeo inspect` to resolve a tag to its digest during CI/CD, then commit the pinned reference.

## Learn More

SLSA Level 1+ and NIST SP 800-190 recommend digest pinning for container supply chain integrity. See the Kubernetes images documentation for details.

**Affected resources:** default/Deployment/kv-e2e-default-web, default/Deployment/kv-e2e-default-worker

</details>

<details>
<summary>Remediation: liveness-readiness-probes (4 resources affected)</summary>

## Why This Matters

Without a liveness probe, Kubernetes cannot detect when a container has become unresponsive or deadlocked. The container continues running and consuming resources while failing to serve traffic. Users experience timeouts and errors until someone manually intervenes.

## How to Fix

Add a liveness probe that checks the container's health:

```yaml
containers:
  - name: app
    livenessProbe:
      httpGet:
        path: /healthz
        port: 8080
      initialDelaySeconds: 15
      periodSeconds: 10
      failureThreshold: 3
```

Use `httpGet` for HTTP services, `tcpSocket` for TCP services, or `exec` with a custom health check script for non-network workloads.

## Learn More

See the Kubernetes documentation on container probes. Set initialDelaySeconds high enough for your application to start, and consider adding a startupProbe for slow-starting containers.

**Affected resources:** default/Deployment/kv-e2e-default-web, default/Deployment/kv-e2e-default-web, default/Deployment/kv-e2e-default-worker, default/Deployment/kv-e2e-default-worker

</details>

<details>
<summary>Remediation: priority-class-missing (2 resources affected)</summary>

## Why This Matters

Without a PriorityClass, pods receive default priority (typically 0) and are among the first to be evicted during resource pressure or node maintenance. This means important application workloads may be killed before less critical ones, leading to unpredictable outages.

## How to Fix

Define PriorityClasses for your workloads and assign them appropriately:

```yaml
apiVersion: scheduling.k8s.io/v1
kind: PriorityClass
metadata:
  name: app-medium
value: 100000
---
# Reference in your workload:
spec:
  priorityClassName: app-medium
```

Create a tiered priority scheme (e.g., app-critical: 500000, app-medium: 100000, app-low: 10000) that reflects your workload importance hierarchy.

## Learn More

Refer to the Kubernetes Pod Priority and Preemption documentation. Establishing a consistent priority scheme across namespaces ensures predictable eviction behavior during resource contention.

**Affected resources:** default/Deployment/kv-e2e-default-web, default/Deployment/kv-e2e-default-worker

</details>

<details>
<summary>Remediation: runtime-class (2 resources affected)</summary>

## Why This Matters

Without a RuntimeClass, pods use the default container runtime (typically runc), which shares the host kernel directly with containers. A kernel vulnerability can allow container escape to the host. Sandboxed runtimes like gVisor or Kata Containers add an additional isolation layer that intercepts system calls or runs containers in lightweight VMs.

## How to Fix

Specify a sandboxed RuntimeClass in the pod spec:

```yaml
spec:
  runtimeClassName: gvisor
```

Available RuntimeClasses depend on your cluster configuration. Common options include `gvisor` (user-space kernel), `kata` (micro-VMs), and `firecracker`. Check your cluster's available RuntimeClasses with `kubectl get runtimeclasses`.

## Learn More

Sandboxed runtimes are especially important for multi-tenant clusters and workloads processing untrusted input. They add latency overhead, so evaluate performance requirements. See the Kubernetes RuntimeClass documentation.

**Affected resources:** default/Deployment/kv-e2e-default-web, default/Deployment/kv-e2e-default-worker

</details>

<details>
<summary>Remediation: topology-spread (2 resources affected)</summary>

## Why This Matters

Without topology spread constraints, the scheduler may place all replicas on the same node or in the same availability zone. If that node or zone fails, your entire service goes down despite having multiple replicas. This negates the high-availability benefits of running multiple pods.

## How to Fix

Add topology spread constraints to distribute replicas across failure domains:

```yaml
spec:
  topologySpreadConstraints:
    - maxSkew: 1
      topologyKey: kubernetes.io/hostname
      whenUnsatisfiable: DoNotSchedule
      labelSelector:
        matchLabels:
          app: my-app
    - maxSkew: 1
      topologyKey: topology.kubernetes.io/zone
      whenUnsatisfiable: ScheduleAnyway
```

Use `kubernetes.io/hostname` for node-level spreading and `topology.kubernetes.io/zone` for zone-level spreading.

## Learn More

See the Kubernetes Pod Topology Spread Constraints documentation. Combining hostname and zone constraints provides both node-level and zone-level fault tolerance.

**Affected resources:** default/Deployment/kv-e2e-default-web, default/Deployment/kv-e2e-default-worker

</details>

### kv-e2e-cluster-no-limits (28 findings — 🟠5 🟡14 🔵9)

| Severity | Check | Resources | Message | Frameworks |
|----------|-------|-----------|---------|-----------|
| 🟠 High | network-policy-missing | kv-e2e-cluster-no-limits/Namespace/kv-e2e-cluster-no-limits | Namespace "kv-e2e-cluster-no-limits" has no NetworkPolicy defined. All pods are unrestricted. | CIS 5.3.2 · MITRE T1046 · NSA 4.1 · NSA 4.2 |
| 🟠 High | automount-token | kv-e2e-cluster-no-limits/Deployment/kv-e2e-no-limits-app | Deployment "kv-e2e-no-limits-app" auto-mounts a ServiceAccount token. Most workloads do not need Kubernetes API access. | CIS 5.1.6 · MITRE T1552.007 · NSA 3.2 |
| 🟠 High | default-service-account | kv-e2e-cluster-no-limits/Deployment/kv-e2e-no-limits-app | Deployment "kv-e2e-no-limits-app" uses the default ServiceAccount, which may have unintended permissions. | CIS 5.1.5 · CIS 5.1.6 · MITRE T1078.001 · NSA 3.1 · NSA 3.2 |
| 🟠 High | privilege-escalation | kv-e2e-cluster-no-limits/Deployment/kv-e2e-no-limits-app (pause) | Container "pause" does not set allowPrivilegeEscalation to false, permitting privilege escalation. | CIS 5.2.6 · MITRE T1068 · MITRE T1611 · NSA 1.1 · NSA 2.1 |
| 🟠 High | run-as-root | kv-e2e-cluster-no-limits/Deployment/kv-e2e-no-limits-app (pause) | Container "pause" does not set runAsNonRoot: true and may run as root. | CIS 5.2.7 · MITRE T1611 · NSA 1.1 |
| 🟡 Medium | network-policy-egress-unrestricted | kv-e2e-cluster-no-limits/Namespace/kv-e2e-cluster-no-limits | Namespace "kv-e2e-cluster-no-limits" has no NetworkPolicy with egress restrictions. Pods can reach any external destination. | CIS 5.3.2 · MITRE T1048 · NSA 4.2 |
| 🟡 Medium | psa-labels-missing | kv-e2e-cluster-no-limits/Namespace/kv-e2e-cluster-no-limits | Namespace "kv-e2e-cluster-no-limits" is missing the pod-security.kubernetes.io/enforce label; pod security is not enforced. | CIS 5.2.1 · MITRE T1610 · NSA 2.1 |
| 🟡 Medium | apparmor-profile | kv-e2e-cluster-no-limits/Deployment/kv-e2e-no-limits-app (pause) | Container "pause" does not have an AppArmor profile set. | CIS 5.6.3 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | capabilities-not-dropped | kv-e2e-cluster-no-limits/Deployment/kv-e2e-no-limits-app (pause) | Container "pause" does not drop ALL capabilities, leaving it with unnecessary default privileges. | CIS 5.2.8 · CIS 5.2.10 · MITRE T1068 · NSA 1.1 |
| 🟡 Medium | image-pull-policy | kv-e2e-cluster-no-limits/Deployment/kv-e2e-no-limits-app (pause) | Container "pause" uses a mutable image tag with pullPolicy "IfNotPresent" (image: registry.k8s.io/pause:3.9), risking stale images. | CIS 5.5.1 · MITRE T1525 · NSA 1.4 |
| 🟡 Medium | psa-restricted-violations | **3 resources** | Deployment "kv-e2e-no-limits-app" container "pause" violates PSS Restricted: runAsNonRoot is not true. | CIS 5.2.1 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | read-only-rootfs | kv-e2e-cluster-no-limits/Deployment/kv-e2e-no-limits-app (pause) | Container "pause" does not have a read-only root filesystem. | CIS 5.6.3 · MITRE T1565.001 · NSA 1.2 |
| 🟡 Medium | resource-limits-missing | kv-e2e-cluster-no-limits/Deployment/kv-e2e-no-limits-app (pause) | Container "pause" is missing both CPU and memory limits. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🟡 Medium | resource-requests-missing | kv-e2e-cluster-no-limits/Deployment/kv-e2e-no-limits-app (pause) | Container "pause" is missing both CPU and memory requests. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🟡 Medium | run-as-group | kv-e2e-cluster-no-limits/Deployment/kv-e2e-no-limits-app (pause) | Container "pause" does not set runAsGroup; the process will run as GID 0 (root group) by default. | CIS 5.2.7 · MITRE T1068 · NSA 1.1 |
| 🟡 Medium | seccomp-profile | kv-e2e-cluster-no-limits/Deployment/kv-e2e-no-limits-app (pause) | Container "pause" does not have a Seccomp profile set at either the container or pod level. | CIS 5.6.2 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | token-projection-config | kv-e2e-cluster-no-limits/Deployment/kv-e2e-no-limits-app | Deployment "kv-e2e-no-limits-app" does not use explicitly configured projected ServiceAccount tokens with expiry and audience restrictions. | CIS 5.1.6 · MITRE T1552.007 · NSA 3.2 |
| 🔵 Low | limit-range-missing | kv-e2e-cluster-no-limits/Namespace/kv-e2e-cluster-no-limits | Namespace "kv-e2e-cluster-no-limits" has no LimitRange defined. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | resource-quota-missing | kv-e2e-cluster-no-limits/Namespace/kv-e2e-cluster-no-limits | Namespace "kv-e2e-cluster-no-limits" has no ResourceQuota defined. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | ephemeral-storage-limits | kv-e2e-cluster-no-limits/Deployment/kv-e2e-no-limits-app (pause) | Container "pause" is missing ephemeral-storage limits. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | image-no-digest | kv-e2e-cluster-no-limits/Deployment/kv-e2e-no-limits-app (pause) | Container "pause" image is not pinned by digest (image: registry.k8s.io/pause:3.9), allowing tag mutation. | CIS 5.5.1 · MITRE T1525 · NSA 1.4 |
| 🔵 Low | liveness-readiness-probes | **2 resources** | Container "pause" has no liveness probe configured. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | priority-class-missing | kv-e2e-cluster-no-limits/Deployment/kv-e2e-no-limits-app | Deployment "kv-e2e-no-limits-app" has no PriorityClass set; it will be evicted first during resource pressure. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | runtime-class | kv-e2e-cluster-no-limits/Deployment/kv-e2e-no-limits-app | Pod "kv-e2e-no-limits-app" does not specify a RuntimeClass, using the default (unsandboxed) runtime. | CIS 5.6.3 · MITRE T1611 · NSA 2.1 |
| 🔵 Low | topology-spread | kv-e2e-cluster-no-limits/Deployment/kv-e2e-no-limits-app | Deployment "kv-e2e-no-limits-app" has no topology spread constraints; all replicas may be scheduled on the same node. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |

<details>
<summary>psa-restricted-violations: 3 affected resources</summary>

- `kv-e2e-cluster-no-limits/Deployment/kv-e2e-no-limits-app (pause)`
- `kv-e2e-cluster-no-limits/Deployment/kv-e2e-no-limits-app (pause)`
- `kv-e2e-cluster-no-limits/Deployment/kv-e2e-no-limits-app (pause)`

</details>

<details>
<summary>liveness-readiness-probes: 2 affected resources</summary>

- `kv-e2e-cluster-no-limits/Deployment/kv-e2e-no-limits-app (pause)`
- `kv-e2e-cluster-no-limits/Deployment/kv-e2e-no-limits-app (pause)`

</details>

<details>
<summary>Remediation: network-policy-missing (1 resources affected)</summary>

## Why This Matters

Without NetworkPolicies, every pod in this namespace can communicate freely with every other pod in the cluster. If an attacker compromises a single pod, they can move laterally to databases, internal APIs, and other sensitive services with no network-level barriers.

## How to Fix

Create a default-deny NetworkPolicy for the namespace, then add targeted allow rules for legitimate traffic:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: my-namespace
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
```

After applying the default-deny, create additional NetworkPolicy resources that whitelist only the specific ingress and egress flows your workloads require.

## Learn More

See the Kubernetes documentation on NetworkPolicies and CIS Kubernetes Benchmark 5.3.2. A CNI plugin that supports NetworkPolicy (Calico, Cilium, Weave Net) must be installed for policies to take effect.

**Affected resources:** kv-e2e-cluster-no-limits/Namespace/kv-e2e-cluster-no-limits

</details>

<details>
<summary>Remediation: automount-token (1 resources affected)</summary>

## Why This Matters

When a ServiceAccount token is auto-mounted, every container in the pod can call the Kubernetes API. If a container is compromised through a vulnerability or misconfiguration, the attacker gains API access to enumerate resources, read secrets, or escalate privileges.

## How to Fix

Disable auto-mounting at the pod spec level for workloads that do not need API access:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      automountServiceAccountToken: false
      containers:
        - name: app
          image: my-app:latest
```

For workloads that do require API access, use projected tokens with bounded lifetime and audience restrictions instead of the default long-lived token.

## Learn More

Refer to the Kubernetes documentation on configuring service accounts for pods and CIS Kubernetes Benchmark 5.1.6 for auto-mount token guidance.

**Affected resources:** kv-e2e-cluster-no-limits/Deployment/kv-e2e-no-limits-app

</details>

<details>
<summary>Remediation: default-service-account (1 resources affected)</summary>

## Why This Matters

The default ServiceAccount is shared by every pod in a namespace. If any pod is compromised, the attacker inherits whatever permissions have been granted to the default account via role bindings, enabling lateral movement across all workloads sharing it.

## How to Fix

Create a dedicated ServiceAccount for each workload and reference it in the pod spec:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-app
  namespace: production
automountServiceAccountToken: false
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      serviceAccountName: my-app
```

Grant only the permissions the workload actually needs via a dedicated Role and RoleBinding.

## Learn More

See the Kubernetes documentation on managing service accounts and CIS Kubernetes Benchmark 5.1.5 for guidance on ensuring default service accounts are not actively used.

**Affected resources:** kv-e2e-cluster-no-limits/Deployment/kv-e2e-no-limits-app

</details>

<details>
<summary>Remediation: privilege-escalation (1 resources affected)</summary>

## Why This Matters

By default, Kubernetes allows containers to escalate privileges via setuid/setgid binaries, which let a process gain more permissions than its parent. An attacker can exploit this using setuid binaries already present in the container image (like `su`, `sudo`, or `ping`) to elevate from a low-privilege user to root.

## How to Fix

Explicitly disable privilege escalation in the container's securityContext:

```yaml
securityContext:
  allowPrivilegeEscalation: false
  runAsNonRoot: true
  capabilities:
    drop: ["ALL"]
```

This blocks the use of setuid/setgid binaries and prevents the no_new_privs Linux flag from being cleared. The vast majority of application containers do not need privilege escalation.

## Learn More

This is required by the Pod Security Standards "Restricted" profile and CIS Benchmark 5.2.5. Disabling privilege escalation is one of the most impactful single-line security improvements you can make.

**Affected resources:** kv-e2e-cluster-no-limits/Deployment/kv-e2e-no-limits-app

</details>

<details>
<summary>Remediation: run-as-root (1 resources affected)</summary>

## Why This Matters

Without `runAsNonRoot: true`, Kubernetes does not enforce non-root execution and the container may default to running as UID 0 depending on the image's USER directive. If the image defaults to root, the container process gains full privileges, increasing the blast radius of any compromise or container escape.

## How to Fix

Enforce non-root execution in the securityContext:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
```

With `runAsNonRoot: true`, Kubernetes will reject the pod at admission time if the container image attempts to run as root. Setting an explicit `runAsUser` provides an additional guarantee.

## Learn More

This aligns with CIS Benchmark 5.2.6 and the Pod Security Standards "Restricted" profile. The `runAsNonRoot` field acts as a safety net even when images change their default USER.

**Affected resources:** kv-e2e-cluster-no-limits/Deployment/kv-e2e-no-limits-app

</details>

<details>
<summary>Remediation: network-policy-egress-unrestricted (1 resources affected)</summary>

## Why This Matters

Without any egress NetworkPolicy in this namespace, pods can freely send traffic to any destination including the public internet. A compromised pod can exfiltrate sensitive data, reach cloud metadata services (e.g., 169.254.169.254), or establish reverse shells to attacker-controlled servers.

## How to Fix

Create a NetworkPolicy with `Egress` in `policyTypes` to restrict outbound traffic. At minimum, allow DNS resolution:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-egress
  namespace: my-namespace
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector: {}
      ports:
        - port: 53
          protocol: UDP
```

Add additional egress rules for specific services your workloads need to reach.

## Learn More

See the Kubernetes NetworkPolicy documentation and CIS Kubernetes Benchmark 5.3.2. Egress controls are a key defense-in-depth measure recommended by the NSA/CISA Kubernetes Hardening Guide.

**Affected resources:** kv-e2e-cluster-no-limits/Namespace/kv-e2e-cluster-no-limits

</details>

<details>
<summary>Remediation: psa-labels-missing (1 resources affected)</summary>

## Why This Matters

Without PSA enforcement labels, any pod configuration is allowed in this namespace, including privileged containers, host namespace access, and root execution. This bypasses Kubernetes' built-in Pod Security Standards and leaves the namespace vulnerable to workloads that could compromise the node.

## How to Fix

Add Pod Security Admission labels to enforce a security profile on all pods in the namespace:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: kv-e2e-cluster-no-limits
  labels:
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

Start with `baseline` enforcement to block known privilege escalations, then upgrade to `restricted` after verifying all workloads are compliant.

## Learn More

See the Kubernetes Pod Security Admission documentation and CIS Kubernetes Benchmark 5.2. The three-tier approach (enforce, audit, warn) allows gradual adoption of stricter profiles.

**Affected resources:** kv-e2e-cluster-no-limits/Namespace/kv-e2e-cluster-no-limits

</details>

<details>
<summary>Remediation: apparmor-profile (1 resources affected)</summary>

## Why This Matters

AppArmor provides mandatory access control (MAC) that restricts which files, network resources, and capabilities a container process can access. Without an AppArmor profile, the container operates without these restrictions, allowing an attacker with code execution to access any file the container user can read and make unrestricted network connections.

## How to Fix

Apply an AppArmor profile in the container's securityContext (Kubernetes 1.30+):

```yaml
securityContext:
  appArmorProfile:
    type: RuntimeDefault
```

The RuntimeDefault profile provides sensible restrictions for most applications. For tighter control, create a custom Localhost profile that only allows the specific file and network access your application needs.

## Learn More

AppArmor is available on Debian/Ubuntu-based nodes. RHEL/CentOS nodes use SELinux instead. Both provide MAC enforcement. Refer to CIS Benchmark 5.7.5 and the Kubernetes AppArmor documentation.

**Affected resources:** kv-e2e-cluster-no-limits/Deployment/kv-e2e-no-limits-app

</details>

<details>
<summary>Remediation: capabilities-not-dropped (1 resources affected)</summary>

## Why This Matters

By default, containers receive a set of Linux capabilities including KILL, SETUID, SETGID, and NET_RAW. These defaults are rarely needed by application code and significantly increase the potential damage from a container compromise. Dropping all capabilities follows the principle of least privilege.

## How to Fix

Explicitly drop all capabilities and selectively add back only what your application needs:

```yaml
securityContext:
  capabilities:
    drop: ["ALL"]
    add: ["NET_BIND_SERVICE"]  # Only if needed
```

Most web applications, API servers, and background workers run perfectly with all capabilities dropped. Test your application after making this change to confirm no functionality is lost.

## Learn More

This is required by the Pod Security Standards "Restricted" profile and aligns with CIS Benchmark 5.2.7. Kubernetes best practice is to treat capability grants as exceptions that require explicit justification.

**Affected resources:** kv-e2e-cluster-no-limits/Deployment/kv-e2e-no-limits-app

</details>

<details>
<summary>Remediation: image-pull-policy (1 resources affected)</summary>

## Why This Matters

When a mutable image tag is used without `imagePullPolicy: Always`, Kubernetes may serve a cached version of the image from the node. If the tag has been updated in the registry (with a security patch or -- worse -- a compromised layer), the running container will not reflect those changes.

## How to Fix

Set `imagePullPolicy: Always` for any container using a mutable tag:

```yaml
containers:
  - name: app
    image: nginx:1.25.3
    imagePullPolicy: Always   # Forces fresh pull each time
```

Alternatively, pin images by digest (`image@sha256:...`), which makes the pull policy irrelevant because the content is immutable.

## Learn More

See the Kubernetes documentation on image pull policies and CIS Kubernetes Benchmark 5.4.2 for pull policy guidance.

**Affected resources:** kv-e2e-cluster-no-limits/Deployment/kv-e2e-no-limits-app

</details>

<details>
<summary>Remediation: psa-restricted-violations (3 resources affected)</summary>

## Why This Matters

Running as root inside a container means that any container escape vulnerability immediately grants root access on the host node. Even without an escape, root inside the container can modify sensitive files, install packages, and access capabilities that non-root users cannot.

## How to Fix

Set `runAsNonRoot: true` and specify a non-root user ID in the security context:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
```

Set this at the pod level to apply to all containers. Ensure your container image supports running as a non-root user (many official images do).

## Learn More

See the Pod Security Standards Restricted profile and CIS Kubernetes Benchmark 5.2.6. Running as non-root is a fundamental container security best practice.

**Affected resources:** kv-e2e-cluster-no-limits/Deployment/kv-e2e-no-limits-app, kv-e2e-cluster-no-limits/Deployment/kv-e2e-no-limits-app, kv-e2e-cluster-no-limits/Deployment/kv-e2e-no-limits-app

</details>

<details>
<summary>Remediation: read-only-rootfs (1 resources affected)</summary>

## Why This Matters

A writable root filesystem allows an attacker who gains code execution in your container to modify application binaries, install attack tools, plant backdoors, or persist malware across container restarts. Making the filesystem read-only eliminates an entire class of post-exploitation techniques.

## How to Fix

Enable a read-only root filesystem and mount writable volumes only where needed:

```yaml
securityContext:
  readOnlyRootFilesystem: true
volumeMounts:
  - name: tmp
    mountPath: /tmp
volumes:
  - name: tmp
    emptyDir: {}
```

Common paths that need write access include /tmp, /var/cache, and /var/run. Mount each as an emptyDir or tmpfs volume rather than making the entire filesystem writable.

## Learn More

This aligns with CIS Benchmark 5.2.4 and the defense-in-depth principle. Combined with dropping capabilities and running as non-root, a read-only filesystem forms a strong container hardening baseline.

**Affected resources:** kv-e2e-cluster-no-limits/Deployment/kv-e2e-no-limits-app

</details>

<details>
<summary>Remediation: resource-limits-missing (1 resources affected)</summary>

## Why This Matters

Without resource limits, a single container can consume all available CPU and memory on a node, starving other workloads and triggering cascading failures. An attacker who compromises an unlimited container can mount a denial-of-service attack against the entire node with a simple fork bomb or memory allocation loop.

## How to Fix

Set both CPU and memory limits based on your application's actual resource usage:

```yaml
resources:
  limits:
    cpu: 500m
    memory: 256Mi
  requests:
    cpu: 100m
    memory: 128Mi
```

Profile your application under load to determine appropriate values. Set limits to handle peak usage and requests to match steady-state consumption.

## Learn More

Use LimitRange objects to enforce default limits at the namespace level. Resource limits also determine the pod's QoS class: pods with equal requests and limits get Guaranteed QoS and are last to be evicted.

**Affected resources:** kv-e2e-cluster-no-limits/Deployment/kv-e2e-no-limits-app

</details>

<details>
<summary>Remediation: resource-requests-missing (1 resources affected)</summary>

## Why This Matters

Resource requests tell the Kubernetes scheduler how much CPU and memory your container needs. Without requests, the scheduler treats the pod as needing zero resources and may pack too many pods onto a single node. This leads to overcommitment, resource contention, throttling, and OOM kills under load.

## How to Fix

Set resource requests based on your application's steady-state usage:

```yaml
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 256Mi
```

Observe your application's actual resource consumption using `kubectl top` or a monitoring tool, then set requests to match the typical steady-state usage.

## Learn More

Resource requests determine the pod's QoS class and scheduling behavior. Pods with requests equal to limits receive Guaranteed QoS. Use Vertical Pod Autoscaler (VPA) to automatically recommend request values.

**Affected resources:** kv-e2e-cluster-no-limits/Deployment/kv-e2e-no-limits-app

</details>

<details>
<summary>Remediation: run-as-group (1 resources affected)</summary>

## Why This Matters

Without an explicit runAsGroup, the container process defaults to GID 0 (the root group). Files and sockets owned by the root group become accessible to the container, including potentially sensitive host files if volumes are mounted. This widens the attack surface unnecessarily.

## How to Fix

Set an explicit non-root group in the securityContext:

```yaml
securityContext:
  runAsGroup: 1000
  runAsUser: 1000
  runAsNonRoot: true
```

Ensure the container image's application files and directories are readable by the specified GID. You may need to adjust file ownership in your Dockerfile with `chown`.

## Learn More

This aligns with CIS Benchmark 5.2.6 and the Pod Security Standards "Restricted" profile. Always set runAsUser, runAsGroup, and runAsNonRoot together for comprehensive identity control.

**Affected resources:** kv-e2e-cluster-no-limits/Deployment/kv-e2e-no-limits-app

</details>

<details>
<summary>Remediation: seccomp-profile (1 resources affected)</summary>

## Why This Matters

Without a Seccomp profile, containers can invoke any of the 300+ Linux system calls, leaving the entire kernel attack surface exposed. Kernel vulnerabilities in obscure syscalls are a primary vector for container escapes. Seccomp filtering blocks dangerous syscalls that legitimate applications never use.

## How to Fix

Apply a Seccomp profile at the container or pod level:

```yaml
securityContext:
  seccompProfile:
    type: RuntimeDefault
```

The RuntimeDefault profile blocks approximately 50 dangerous syscalls while allowing normal application behavior. For stricter controls, use a custom Localhost profile tailored to your application's needs. Set the profile at the pod level to apply it to all containers.

## Learn More

Seccomp profiles are required by the Pod Security Standards "Restricted" profile and CIS Benchmark 5.7.2. Use tools like `strace` or the Security Profiles Operator to generate custom profiles for your workloads.

**Affected resources:** kv-e2e-cluster-no-limits/Deployment/kv-e2e-no-limits-app

</details>

<details>
<summary>Remediation: token-projection-config (1 resources affected)</summary>

## Why This Matters

Without explicit projection configuration, ServiceAccount tokens use Kubernetes defaults: no audience restriction and a long expiration. A stolen token remains valid for an extended period and can be used against any API server endpoint, widening the blast radius of a compromise.

## How to Fix

Add a projected volume with explicit expiration and audience:

```yaml
spec:
  volumes:
    - name: token
      projected:
        sources:
          - serviceAccountToken:
              expirationSeconds: 3600
              audience: my-api
              path: token
  containers:
    - name: app
      volumeMounts:
        - name: token
          mountPath: /var/run/secrets/tokens
          readOnly: true
```

Projected tokens auto-rotate before expiry and are rejected by endpoints outside the specified audience.

## Learn More

See the Kubernetes documentation on projected volumes and service account token volume projection for detailed configuration options.

**Affected resources:** kv-e2e-cluster-no-limits/Deployment/kv-e2e-no-limits-app

</details>

<details>
<summary>Remediation: limit-range-missing (1 resources affected)</summary>

## Why This Matters

Without a LimitRange, any container can be created without resource constraints. A single runaway or malicious pod can consume all node CPU and memory, causing denial of service for other workloads on the same node.

## How to Fix

Create a LimitRange in the namespace to set default and maximum resource constraints:

```yaml
apiVersion: v1
kind: LimitRange
metadata:
  name: default-limits
  namespace: my-app
spec:
  limits:
    - type: Container
      default:
        cpu: 500m
        memory: 256Mi
      defaultRequest:
        cpu: 100m
        memory: 128Mi
      max:
        cpu: "2"
        memory: 1Gi
```

Containers that omit resource requests/limits will inherit these defaults automatically.

## Learn More

CIS Kubernetes Benchmark 5.2.1 recommends LimitRanges for resource governance. See https://kubernetes.io/docs/concepts/policy/limit-range/ for configuration details.

**Affected resources:** kv-e2e-cluster-no-limits/Namespace/kv-e2e-cluster-no-limits

</details>

<details>
<summary>Remediation: resource-quota-missing (1 resources affected)</summary>

## Why This Matters

Without a ResourceQuota, a single namespace can consume the entire cluster's CPU, memory, and storage. This creates a noisy-neighbor problem where one team's workloads starve others, and makes capacity planning impossible.

## How to Fix

Create a ResourceQuota to cap the namespace's total resource consumption:

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: compute-quota
  namespace: my-app
spec:
  hard:
    requests.cpu: "10"
    requests.memory: 20Gi
    limits.cpu: "20"
    limits.memory: 40Gi
    pods: "50"
    services: "10"
```

Tune quota values based on the namespace's actual workload requirements and cluster capacity.

## Learn More

CIS Kubernetes Benchmark 5.2.2 recommends ResourceQuotas for multi-tenant clusters. See https://kubernetes.io/docs/concepts/policy/resource-quotas/ for quota configuration and enforcement behavior.

**Affected resources:** kv-e2e-cluster-no-limits/Namespace/kv-e2e-cluster-no-limits

</details>

<details>
<summary>Remediation: ephemeral-storage-limits (1 resources affected)</summary>

## Why This Matters

Ephemeral storage includes container logs, emptyDir volumes, and the writable container layer. Without limits, a single container can fill the node's root disk, triggering eviction of all pods on that node and potentially causing a cascading failure across your cluster. This is a common denial-of-service vector.

## How to Fix

Set ephemeral-storage limits alongside your CPU and memory limits:

```yaml
resources:
  limits:
    ephemeral-storage: 1Gi
  requests:
    ephemeral-storage: 500Mi
```

Estimate your application's disk usage from logs, temporary files, and cache data. If your application writes large temporary files, consider using a PersistentVolumeClaim instead of ephemeral storage.

## Learn More

The kubelet evicts pods that exceed their ephemeral-storage limit. Use LimitRange to set default ephemeral-storage limits at the namespace level to catch containers that omit this setting.

**Affected resources:** kv-e2e-cluster-no-limits/Deployment/kv-e2e-no-limits-app

</details>

<details>
<summary>Remediation: image-no-digest (1 resources affected)</summary>

## Why This Matters

Image tags are mutable pointers -- a registry administrator or attacker can re-push a different image under the same tag. Without a digest, you have no cryptographic guarantee that the image you deploy is the one you tested.

## How to Fix

Pin images by their SHA-256 content digest for a fully immutable reference:

```yaml
containers:
  - name: app
    image: nginx@sha256:a8281ce420348a01ea6e   # Immutable
```

Use `crane digest nginx:1.25.3` or `skopeo inspect` to resolve a tag to its digest during CI/CD, then commit the pinned reference.

## Learn More

SLSA Level 1+ and NIST SP 800-190 recommend digest pinning for container supply chain integrity. See the Kubernetes images documentation for details.

**Affected resources:** kv-e2e-cluster-no-limits/Deployment/kv-e2e-no-limits-app

</details>

<details>
<summary>Remediation: liveness-readiness-probes (2 resources affected)</summary>

## Why This Matters

Without a liveness probe, Kubernetes cannot detect when a container has become unresponsive or deadlocked. The container continues running and consuming resources while failing to serve traffic. Users experience timeouts and errors until someone manually intervenes.

## How to Fix

Add a liveness probe that checks the container's health:

```yaml
containers:
  - name: app
    livenessProbe:
      httpGet:
        path: /healthz
        port: 8080
      initialDelaySeconds: 15
      periodSeconds: 10
      failureThreshold: 3
```

Use `httpGet` for HTTP services, `tcpSocket` for TCP services, or `exec` with a custom health check script for non-network workloads.

## Learn More

See the Kubernetes documentation on container probes. Set initialDelaySeconds high enough for your application to start, and consider adding a startupProbe for slow-starting containers.

**Affected resources:** kv-e2e-cluster-no-limits/Deployment/kv-e2e-no-limits-app, kv-e2e-cluster-no-limits/Deployment/kv-e2e-no-limits-app

</details>

<details>
<summary>Remediation: priority-class-missing (1 resources affected)</summary>

## Why This Matters

Without a PriorityClass, pods receive default priority (typically 0) and are among the first to be evicted during resource pressure or node maintenance. This means important application workloads may be killed before less critical ones, leading to unpredictable outages.

## How to Fix

Define PriorityClasses for your workloads and assign them appropriately:

```yaml
apiVersion: scheduling.k8s.io/v1
kind: PriorityClass
metadata:
  name: app-medium
value: 100000
---
# Reference in your workload:
spec:
  priorityClassName: app-medium
```

Create a tiered priority scheme (e.g., app-critical: 500000, app-medium: 100000, app-low: 10000) that reflects your workload importance hierarchy.

## Learn More

Refer to the Kubernetes Pod Priority and Preemption documentation. Establishing a consistent priority scheme across namespaces ensures predictable eviction behavior during resource contention.

**Affected resources:** kv-e2e-cluster-no-limits/Deployment/kv-e2e-no-limits-app

</details>

<details>
<summary>Remediation: runtime-class (1 resources affected)</summary>

## Why This Matters

Without a RuntimeClass, pods use the default container runtime (typically runc), which shares the host kernel directly with containers. A kernel vulnerability can allow container escape to the host. Sandboxed runtimes like gVisor or Kata Containers add an additional isolation layer that intercepts system calls or runs containers in lightweight VMs.

## How to Fix

Specify a sandboxed RuntimeClass in the pod spec:

```yaml
spec:
  runtimeClassName: gvisor
```

Available RuntimeClasses depend on your cluster configuration. Common options include `gvisor` (user-space kernel), `kata` (micro-VMs), and `firecracker`. Check your cluster's available RuntimeClasses with `kubectl get runtimeclasses`.

## Learn More

Sandboxed runtimes are especially important for multi-tenant clusters and workloads processing untrusted input. They add latency overhead, so evaluate performance requirements. See the Kubernetes RuntimeClass documentation.

**Affected resources:** kv-e2e-cluster-no-limits/Deployment/kv-e2e-no-limits-app

</details>

<details>
<summary>Remediation: topology-spread (1 resources affected)</summary>

## Why This Matters

Without topology spread constraints, the scheduler may place all replicas on the same node or in the same availability zone. If that node or zone fails, your entire service goes down despite having multiple replicas. This negates the high-availability benefits of running multiple pods.

## How to Fix

Add topology spread constraints to distribute replicas across failure domains:

```yaml
spec:
  topologySpreadConstraints:
    - maxSkew: 1
      topologyKey: kubernetes.io/hostname
      whenUnsatisfiable: DoNotSchedule
      labelSelector:
        matchLabels:
          app: my-app
    - maxSkew: 1
      topologyKey: topology.kubernetes.io/zone
      whenUnsatisfiable: ScheduleAnyway
```

Use `kubernetes.io/hostname` for node-level spreading and `topology.kubernetes.io/zone` for zone-level spreading.

## Learn More

See the Kubernetes Pod Topology Spread Constraints documentation. Combining hostname and zone constraints provides both node-level and zone-level fault tolerance.

**Affected resources:** kv-e2e-cluster-no-limits/Deployment/kv-e2e-no-limits-app

</details>

### kv-e2e-cluster-no-quota (28 findings — 🟠5 🟡14 🔵9)

| Severity | Check | Resources | Message | Frameworks |
|----------|-------|-----------|---------|-----------|
| 🟠 High | network-policy-missing | kv-e2e-cluster-no-quota/Namespace/kv-e2e-cluster-no-quota | Namespace "kv-e2e-cluster-no-quota" has no NetworkPolicy defined. All pods are unrestricted. | CIS 5.3.2 · MITRE T1046 · NSA 4.1 · NSA 4.2 |
| 🟠 High | automount-token | kv-e2e-cluster-no-quota/Deployment/kv-e2e-unconstrained-app | Deployment "kv-e2e-unconstrained-app" auto-mounts a ServiceAccount token. Most workloads do not need Kubernetes API access. | CIS 5.1.6 · MITRE T1552.007 · NSA 3.2 |
| 🟠 High | default-service-account | kv-e2e-cluster-no-quota/Deployment/kv-e2e-unconstrained-app | Deployment "kv-e2e-unconstrained-app" uses the default ServiceAccount, which may have unintended permissions. | CIS 5.1.5 · CIS 5.1.6 · MITRE T1078.001 · NSA 3.1 · NSA 3.2 |
| 🟠 High | privilege-escalation | kv-e2e-cluster-no-quota/Deployment/kv-e2e-unconstrained-app (pause) | Container "pause" does not set allowPrivilegeEscalation to false, permitting privilege escalation. | CIS 5.2.6 · MITRE T1068 · MITRE T1611 · NSA 1.1 · NSA 2.1 |
| 🟠 High | run-as-root | kv-e2e-cluster-no-quota/Deployment/kv-e2e-unconstrained-app (pause) | Container "pause" does not set runAsNonRoot: true and may run as root. | CIS 5.2.7 · MITRE T1611 · NSA 1.1 |
| 🟡 Medium | network-policy-egress-unrestricted | kv-e2e-cluster-no-quota/Namespace/kv-e2e-cluster-no-quota | Namespace "kv-e2e-cluster-no-quota" has no NetworkPolicy with egress restrictions. Pods can reach any external destination. | CIS 5.3.2 · MITRE T1048 · NSA 4.2 |
| 🟡 Medium | psa-labels-missing | kv-e2e-cluster-no-quota/Namespace/kv-e2e-cluster-no-quota | Namespace "kv-e2e-cluster-no-quota" is missing the pod-security.kubernetes.io/enforce label; pod security is not enforced. | CIS 5.2.1 · MITRE T1610 · NSA 2.1 |
| 🟡 Medium | apparmor-profile | kv-e2e-cluster-no-quota/Deployment/kv-e2e-unconstrained-app (pause) | Container "pause" does not have an AppArmor profile set. | CIS 5.6.3 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | capabilities-not-dropped | kv-e2e-cluster-no-quota/Deployment/kv-e2e-unconstrained-app (pause) | Container "pause" does not drop ALL capabilities, leaving it with unnecessary default privileges. | CIS 5.2.8 · CIS 5.2.10 · MITRE T1068 · NSA 1.1 |
| 🟡 Medium | image-pull-policy | kv-e2e-cluster-no-quota/Deployment/kv-e2e-unconstrained-app (pause) | Container "pause" uses a mutable image tag with pullPolicy "IfNotPresent" (image: registry.k8s.io/pause:3.9), risking stale images. | CIS 5.5.1 · MITRE T1525 · NSA 1.4 |
| 🟡 Medium | psa-restricted-violations | **3 resources** | Deployment "kv-e2e-unconstrained-app" container "pause" violates PSS Restricted: runAsNonRoot is not true. | CIS 5.2.1 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | read-only-rootfs | kv-e2e-cluster-no-quota/Deployment/kv-e2e-unconstrained-app (pause) | Container "pause" does not have a read-only root filesystem. | CIS 5.6.3 · MITRE T1565.001 · NSA 1.2 |
| 🟡 Medium | resource-limits-missing | kv-e2e-cluster-no-quota/Deployment/kv-e2e-unconstrained-app (pause) | Container "pause" is missing both CPU and memory limits. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🟡 Medium | resource-requests-missing | kv-e2e-cluster-no-quota/Deployment/kv-e2e-unconstrained-app (pause) | Container "pause" is missing both CPU and memory requests. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🟡 Medium | run-as-group | kv-e2e-cluster-no-quota/Deployment/kv-e2e-unconstrained-app (pause) | Container "pause" does not set runAsGroup; the process will run as GID 0 (root group) by default. | CIS 5.2.7 · MITRE T1068 · NSA 1.1 |
| 🟡 Medium | seccomp-profile | kv-e2e-cluster-no-quota/Deployment/kv-e2e-unconstrained-app (pause) | Container "pause" does not have a Seccomp profile set at either the container or pod level. | CIS 5.6.2 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | token-projection-config | kv-e2e-cluster-no-quota/Deployment/kv-e2e-unconstrained-app | Deployment "kv-e2e-unconstrained-app" does not use explicitly configured projected ServiceAccount tokens with expiry and audience restrictions. | CIS 5.1.6 · MITRE T1552.007 · NSA 3.2 |
| 🔵 Low | limit-range-missing | kv-e2e-cluster-no-quota/Namespace/kv-e2e-cluster-no-quota | Namespace "kv-e2e-cluster-no-quota" has no LimitRange defined. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | resource-quota-missing | kv-e2e-cluster-no-quota/Namespace/kv-e2e-cluster-no-quota | Namespace "kv-e2e-cluster-no-quota" has no ResourceQuota defined. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | ephemeral-storage-limits | kv-e2e-cluster-no-quota/Deployment/kv-e2e-unconstrained-app (pause) | Container "pause" is missing ephemeral-storage limits. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | image-no-digest | kv-e2e-cluster-no-quota/Deployment/kv-e2e-unconstrained-app (pause) | Container "pause" image is not pinned by digest (image: registry.k8s.io/pause:3.9), allowing tag mutation. | CIS 5.5.1 · MITRE T1525 · NSA 1.4 |
| 🔵 Low | liveness-readiness-probes | **2 resources** | Container "pause" has no liveness probe configured. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | priority-class-missing | kv-e2e-cluster-no-quota/Deployment/kv-e2e-unconstrained-app | Deployment "kv-e2e-unconstrained-app" has no PriorityClass set; it will be evicted first during resource pressure. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | runtime-class | kv-e2e-cluster-no-quota/Deployment/kv-e2e-unconstrained-app | Pod "kv-e2e-unconstrained-app" does not specify a RuntimeClass, using the default (unsandboxed) runtime. | CIS 5.6.3 · MITRE T1611 · NSA 2.1 |
| 🔵 Low | topology-spread | kv-e2e-cluster-no-quota/Deployment/kv-e2e-unconstrained-app | Deployment "kv-e2e-unconstrained-app" has no topology spread constraints; all replicas may be scheduled on the same node. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |

<details>
<summary>psa-restricted-violations: 3 affected resources</summary>

- `kv-e2e-cluster-no-quota/Deployment/kv-e2e-unconstrained-app (pause)`
- `kv-e2e-cluster-no-quota/Deployment/kv-e2e-unconstrained-app (pause)`
- `kv-e2e-cluster-no-quota/Deployment/kv-e2e-unconstrained-app (pause)`

</details>

<details>
<summary>liveness-readiness-probes: 2 affected resources</summary>

- `kv-e2e-cluster-no-quota/Deployment/kv-e2e-unconstrained-app (pause)`
- `kv-e2e-cluster-no-quota/Deployment/kv-e2e-unconstrained-app (pause)`

</details>

<details>
<summary>Remediation: network-policy-missing (1 resources affected)</summary>

## Why This Matters

Without NetworkPolicies, every pod in this namespace can communicate freely with every other pod in the cluster. If an attacker compromises a single pod, they can move laterally to databases, internal APIs, and other sensitive services with no network-level barriers.

## How to Fix

Create a default-deny NetworkPolicy for the namespace, then add targeted allow rules for legitimate traffic:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: my-namespace
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
```

After applying the default-deny, create additional NetworkPolicy resources that whitelist only the specific ingress and egress flows your workloads require.

## Learn More

See the Kubernetes documentation on NetworkPolicies and CIS Kubernetes Benchmark 5.3.2. A CNI plugin that supports NetworkPolicy (Calico, Cilium, Weave Net) must be installed for policies to take effect.

**Affected resources:** kv-e2e-cluster-no-quota/Namespace/kv-e2e-cluster-no-quota

</details>

<details>
<summary>Remediation: automount-token (1 resources affected)</summary>

## Why This Matters

When a ServiceAccount token is auto-mounted, every container in the pod can call the Kubernetes API. If a container is compromised through a vulnerability or misconfiguration, the attacker gains API access to enumerate resources, read secrets, or escalate privileges.

## How to Fix

Disable auto-mounting at the pod spec level for workloads that do not need API access:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      automountServiceAccountToken: false
      containers:
        - name: app
          image: my-app:latest
```

For workloads that do require API access, use projected tokens with bounded lifetime and audience restrictions instead of the default long-lived token.

## Learn More

Refer to the Kubernetes documentation on configuring service accounts for pods and CIS Kubernetes Benchmark 5.1.6 for auto-mount token guidance.

**Affected resources:** kv-e2e-cluster-no-quota/Deployment/kv-e2e-unconstrained-app

</details>

<details>
<summary>Remediation: default-service-account (1 resources affected)</summary>

## Why This Matters

The default ServiceAccount is shared by every pod in a namespace. If any pod is compromised, the attacker inherits whatever permissions have been granted to the default account via role bindings, enabling lateral movement across all workloads sharing it.

## How to Fix

Create a dedicated ServiceAccount for each workload and reference it in the pod spec:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-app
  namespace: production
automountServiceAccountToken: false
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      serviceAccountName: my-app
```

Grant only the permissions the workload actually needs via a dedicated Role and RoleBinding.

## Learn More

See the Kubernetes documentation on managing service accounts and CIS Kubernetes Benchmark 5.1.5 for guidance on ensuring default service accounts are not actively used.

**Affected resources:** kv-e2e-cluster-no-quota/Deployment/kv-e2e-unconstrained-app

</details>

<details>
<summary>Remediation: privilege-escalation (1 resources affected)</summary>

## Why This Matters

By default, Kubernetes allows containers to escalate privileges via setuid/setgid binaries, which let a process gain more permissions than its parent. An attacker can exploit this using setuid binaries already present in the container image (like `su`, `sudo`, or `ping`) to elevate from a low-privilege user to root.

## How to Fix

Explicitly disable privilege escalation in the container's securityContext:

```yaml
securityContext:
  allowPrivilegeEscalation: false
  runAsNonRoot: true
  capabilities:
    drop: ["ALL"]
```

This blocks the use of setuid/setgid binaries and prevents the no_new_privs Linux flag from being cleared. The vast majority of application containers do not need privilege escalation.

## Learn More

This is required by the Pod Security Standards "Restricted" profile and CIS Benchmark 5.2.5. Disabling privilege escalation is one of the most impactful single-line security improvements you can make.

**Affected resources:** kv-e2e-cluster-no-quota/Deployment/kv-e2e-unconstrained-app

</details>

<details>
<summary>Remediation: run-as-root (1 resources affected)</summary>

## Why This Matters

Without `runAsNonRoot: true`, Kubernetes does not enforce non-root execution and the container may default to running as UID 0 depending on the image's USER directive. If the image defaults to root, the container process gains full privileges, increasing the blast radius of any compromise or container escape.

## How to Fix

Enforce non-root execution in the securityContext:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
```

With `runAsNonRoot: true`, Kubernetes will reject the pod at admission time if the container image attempts to run as root. Setting an explicit `runAsUser` provides an additional guarantee.

## Learn More

This aligns with CIS Benchmark 5.2.6 and the Pod Security Standards "Restricted" profile. The `runAsNonRoot` field acts as a safety net even when images change their default USER.

**Affected resources:** kv-e2e-cluster-no-quota/Deployment/kv-e2e-unconstrained-app

</details>

<details>
<summary>Remediation: network-policy-egress-unrestricted (1 resources affected)</summary>

## Why This Matters

Without any egress NetworkPolicy in this namespace, pods can freely send traffic to any destination including the public internet. A compromised pod can exfiltrate sensitive data, reach cloud metadata services (e.g., 169.254.169.254), or establish reverse shells to attacker-controlled servers.

## How to Fix

Create a NetworkPolicy with `Egress` in `policyTypes` to restrict outbound traffic. At minimum, allow DNS resolution:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-egress
  namespace: my-namespace
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector: {}
      ports:
        - port: 53
          protocol: UDP
```

Add additional egress rules for specific services your workloads need to reach.

## Learn More

See the Kubernetes NetworkPolicy documentation and CIS Kubernetes Benchmark 5.3.2. Egress controls are a key defense-in-depth measure recommended by the NSA/CISA Kubernetes Hardening Guide.

**Affected resources:** kv-e2e-cluster-no-quota/Namespace/kv-e2e-cluster-no-quota

</details>

<details>
<summary>Remediation: psa-labels-missing (1 resources affected)</summary>

## Why This Matters

Without PSA enforcement labels, any pod configuration is allowed in this namespace, including privileged containers, host namespace access, and root execution. This bypasses Kubernetes' built-in Pod Security Standards and leaves the namespace vulnerable to workloads that could compromise the node.

## How to Fix

Add Pod Security Admission labels to enforce a security profile on all pods in the namespace:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: kv-e2e-cluster-no-quota
  labels:
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

Start with `baseline` enforcement to block known privilege escalations, then upgrade to `restricted` after verifying all workloads are compliant.

## Learn More

See the Kubernetes Pod Security Admission documentation and CIS Kubernetes Benchmark 5.2. The three-tier approach (enforce, audit, warn) allows gradual adoption of stricter profiles.

**Affected resources:** kv-e2e-cluster-no-quota/Namespace/kv-e2e-cluster-no-quota

</details>

<details>
<summary>Remediation: apparmor-profile (1 resources affected)</summary>

## Why This Matters

AppArmor provides mandatory access control (MAC) that restricts which files, network resources, and capabilities a container process can access. Without an AppArmor profile, the container operates without these restrictions, allowing an attacker with code execution to access any file the container user can read and make unrestricted network connections.

## How to Fix

Apply an AppArmor profile in the container's securityContext (Kubernetes 1.30+):

```yaml
securityContext:
  appArmorProfile:
    type: RuntimeDefault
```

The RuntimeDefault profile provides sensible restrictions for most applications. For tighter control, create a custom Localhost profile that only allows the specific file and network access your application needs.

## Learn More

AppArmor is available on Debian/Ubuntu-based nodes. RHEL/CentOS nodes use SELinux instead. Both provide MAC enforcement. Refer to CIS Benchmark 5.7.5 and the Kubernetes AppArmor documentation.

**Affected resources:** kv-e2e-cluster-no-quota/Deployment/kv-e2e-unconstrained-app

</details>

<details>
<summary>Remediation: capabilities-not-dropped (1 resources affected)</summary>

## Why This Matters

By default, containers receive a set of Linux capabilities including KILL, SETUID, SETGID, and NET_RAW. These defaults are rarely needed by application code and significantly increase the potential damage from a container compromise. Dropping all capabilities follows the principle of least privilege.

## How to Fix

Explicitly drop all capabilities and selectively add back only what your application needs:

```yaml
securityContext:
  capabilities:
    drop: ["ALL"]
    add: ["NET_BIND_SERVICE"]  # Only if needed
```

Most web applications, API servers, and background workers run perfectly with all capabilities dropped. Test your application after making this change to confirm no functionality is lost.

## Learn More

This is required by the Pod Security Standards "Restricted" profile and aligns with CIS Benchmark 5.2.7. Kubernetes best practice is to treat capability grants as exceptions that require explicit justification.

**Affected resources:** kv-e2e-cluster-no-quota/Deployment/kv-e2e-unconstrained-app

</details>

<details>
<summary>Remediation: image-pull-policy (1 resources affected)</summary>

## Why This Matters

When a mutable image tag is used without `imagePullPolicy: Always`, Kubernetes may serve a cached version of the image from the node. If the tag has been updated in the registry (with a security patch or -- worse -- a compromised layer), the running container will not reflect those changes.

## How to Fix

Set `imagePullPolicy: Always` for any container using a mutable tag:

```yaml
containers:
  - name: app
    image: nginx:1.25.3
    imagePullPolicy: Always   # Forces fresh pull each time
```

Alternatively, pin images by digest (`image@sha256:...`), which makes the pull policy irrelevant because the content is immutable.

## Learn More

See the Kubernetes documentation on image pull policies and CIS Kubernetes Benchmark 5.4.2 for pull policy guidance.

**Affected resources:** kv-e2e-cluster-no-quota/Deployment/kv-e2e-unconstrained-app

</details>

<details>
<summary>Remediation: psa-restricted-violations (3 resources affected)</summary>

## Why This Matters

Running as root inside a container means that any container escape vulnerability immediately grants root access on the host node. Even without an escape, root inside the container can modify sensitive files, install packages, and access capabilities that non-root users cannot.

## How to Fix

Set `runAsNonRoot: true` and specify a non-root user ID in the security context:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
```

Set this at the pod level to apply to all containers. Ensure your container image supports running as a non-root user (many official images do).

## Learn More

See the Pod Security Standards Restricted profile and CIS Kubernetes Benchmark 5.2.6. Running as non-root is a fundamental container security best practice.

**Affected resources:** kv-e2e-cluster-no-quota/Deployment/kv-e2e-unconstrained-app, kv-e2e-cluster-no-quota/Deployment/kv-e2e-unconstrained-app, kv-e2e-cluster-no-quota/Deployment/kv-e2e-unconstrained-app

</details>

<details>
<summary>Remediation: read-only-rootfs (1 resources affected)</summary>

## Why This Matters

A writable root filesystem allows an attacker who gains code execution in your container to modify application binaries, install attack tools, plant backdoors, or persist malware across container restarts. Making the filesystem read-only eliminates an entire class of post-exploitation techniques.

## How to Fix

Enable a read-only root filesystem and mount writable volumes only where needed:

```yaml
securityContext:
  readOnlyRootFilesystem: true
volumeMounts:
  - name: tmp
    mountPath: /tmp
volumes:
  - name: tmp
    emptyDir: {}
```

Common paths that need write access include /tmp, /var/cache, and /var/run. Mount each as an emptyDir or tmpfs volume rather than making the entire filesystem writable.

## Learn More

This aligns with CIS Benchmark 5.2.4 and the defense-in-depth principle. Combined with dropping capabilities and running as non-root, a read-only filesystem forms a strong container hardening baseline.

**Affected resources:** kv-e2e-cluster-no-quota/Deployment/kv-e2e-unconstrained-app

</details>

<details>
<summary>Remediation: resource-limits-missing (1 resources affected)</summary>

## Why This Matters

Without resource limits, a single container can consume all available CPU and memory on a node, starving other workloads and triggering cascading failures. An attacker who compromises an unlimited container can mount a denial-of-service attack against the entire node with a simple fork bomb or memory allocation loop.

## How to Fix

Set both CPU and memory limits based on your application's actual resource usage:

```yaml
resources:
  limits:
    cpu: 500m
    memory: 256Mi
  requests:
    cpu: 100m
    memory: 128Mi
```

Profile your application under load to determine appropriate values. Set limits to handle peak usage and requests to match steady-state consumption.

## Learn More

Use LimitRange objects to enforce default limits at the namespace level. Resource limits also determine the pod's QoS class: pods with equal requests and limits get Guaranteed QoS and are last to be evicted.

**Affected resources:** kv-e2e-cluster-no-quota/Deployment/kv-e2e-unconstrained-app

</details>

<details>
<summary>Remediation: resource-requests-missing (1 resources affected)</summary>

## Why This Matters

Resource requests tell the Kubernetes scheduler how much CPU and memory your container needs. Without requests, the scheduler treats the pod as needing zero resources and may pack too many pods onto a single node. This leads to overcommitment, resource contention, throttling, and OOM kills under load.

## How to Fix

Set resource requests based on your application's steady-state usage:

```yaml
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 256Mi
```

Observe your application's actual resource consumption using `kubectl top` or a monitoring tool, then set requests to match the typical steady-state usage.

## Learn More

Resource requests determine the pod's QoS class and scheduling behavior. Pods with requests equal to limits receive Guaranteed QoS. Use Vertical Pod Autoscaler (VPA) to automatically recommend request values.

**Affected resources:** kv-e2e-cluster-no-quota/Deployment/kv-e2e-unconstrained-app

</details>

<details>
<summary>Remediation: run-as-group (1 resources affected)</summary>

## Why This Matters

Without an explicit runAsGroup, the container process defaults to GID 0 (the root group). Files and sockets owned by the root group become accessible to the container, including potentially sensitive host files if volumes are mounted. This widens the attack surface unnecessarily.

## How to Fix

Set an explicit non-root group in the securityContext:

```yaml
securityContext:
  runAsGroup: 1000
  runAsUser: 1000
  runAsNonRoot: true
```

Ensure the container image's application files and directories are readable by the specified GID. You may need to adjust file ownership in your Dockerfile with `chown`.

## Learn More

This aligns with CIS Benchmark 5.2.6 and the Pod Security Standards "Restricted" profile. Always set runAsUser, runAsGroup, and runAsNonRoot together for comprehensive identity control.

**Affected resources:** kv-e2e-cluster-no-quota/Deployment/kv-e2e-unconstrained-app

</details>

<details>
<summary>Remediation: seccomp-profile (1 resources affected)</summary>

## Why This Matters

Without a Seccomp profile, containers can invoke any of the 300+ Linux system calls, leaving the entire kernel attack surface exposed. Kernel vulnerabilities in obscure syscalls are a primary vector for container escapes. Seccomp filtering blocks dangerous syscalls that legitimate applications never use.

## How to Fix

Apply a Seccomp profile at the container or pod level:

```yaml
securityContext:
  seccompProfile:
    type: RuntimeDefault
```

The RuntimeDefault profile blocks approximately 50 dangerous syscalls while allowing normal application behavior. For stricter controls, use a custom Localhost profile tailored to your application's needs. Set the profile at the pod level to apply it to all containers.

## Learn More

Seccomp profiles are required by the Pod Security Standards "Restricted" profile and CIS Benchmark 5.7.2. Use tools like `strace` or the Security Profiles Operator to generate custom profiles for your workloads.

**Affected resources:** kv-e2e-cluster-no-quota/Deployment/kv-e2e-unconstrained-app

</details>

<details>
<summary>Remediation: token-projection-config (1 resources affected)</summary>

## Why This Matters

Without explicit projection configuration, ServiceAccount tokens use Kubernetes defaults: no audience restriction and a long expiration. A stolen token remains valid for an extended period and can be used against any API server endpoint, widening the blast radius of a compromise.

## How to Fix

Add a projected volume with explicit expiration and audience:

```yaml
spec:
  volumes:
    - name: token
      projected:
        sources:
          - serviceAccountToken:
              expirationSeconds: 3600
              audience: my-api
              path: token
  containers:
    - name: app
      volumeMounts:
        - name: token
          mountPath: /var/run/secrets/tokens
          readOnly: true
```

Projected tokens auto-rotate before expiry and are rejected by endpoints outside the specified audience.

## Learn More

See the Kubernetes documentation on projected volumes and service account token volume projection for detailed configuration options.

**Affected resources:** kv-e2e-cluster-no-quota/Deployment/kv-e2e-unconstrained-app

</details>

<details>
<summary>Remediation: limit-range-missing (1 resources affected)</summary>

## Why This Matters

Without a LimitRange, any container can be created without resource constraints. A single runaway or malicious pod can consume all node CPU and memory, causing denial of service for other workloads on the same node.

## How to Fix

Create a LimitRange in the namespace to set default and maximum resource constraints:

```yaml
apiVersion: v1
kind: LimitRange
metadata:
  name: default-limits
  namespace: my-app
spec:
  limits:
    - type: Container
      default:
        cpu: 500m
        memory: 256Mi
      defaultRequest:
        cpu: 100m
        memory: 128Mi
      max:
        cpu: "2"
        memory: 1Gi
```

Containers that omit resource requests/limits will inherit these defaults automatically.

## Learn More

CIS Kubernetes Benchmark 5.2.1 recommends LimitRanges for resource governance. See https://kubernetes.io/docs/concepts/policy/limit-range/ for configuration details.

**Affected resources:** kv-e2e-cluster-no-quota/Namespace/kv-e2e-cluster-no-quota

</details>

<details>
<summary>Remediation: resource-quota-missing (1 resources affected)</summary>

## Why This Matters

Without a ResourceQuota, a single namespace can consume the entire cluster's CPU, memory, and storage. This creates a noisy-neighbor problem where one team's workloads starve others, and makes capacity planning impossible.

## How to Fix

Create a ResourceQuota to cap the namespace's total resource consumption:

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: compute-quota
  namespace: my-app
spec:
  hard:
    requests.cpu: "10"
    requests.memory: 20Gi
    limits.cpu: "20"
    limits.memory: 40Gi
    pods: "50"
    services: "10"
```

Tune quota values based on the namespace's actual workload requirements and cluster capacity.

## Learn More

CIS Kubernetes Benchmark 5.2.2 recommends ResourceQuotas for multi-tenant clusters. See https://kubernetes.io/docs/concepts/policy/resource-quotas/ for quota configuration and enforcement behavior.

**Affected resources:** kv-e2e-cluster-no-quota/Namespace/kv-e2e-cluster-no-quota

</details>

<details>
<summary>Remediation: ephemeral-storage-limits (1 resources affected)</summary>

## Why This Matters

Ephemeral storage includes container logs, emptyDir volumes, and the writable container layer. Without limits, a single container can fill the node's root disk, triggering eviction of all pods on that node and potentially causing a cascading failure across your cluster. This is a common denial-of-service vector.

## How to Fix

Set ephemeral-storage limits alongside your CPU and memory limits:

```yaml
resources:
  limits:
    ephemeral-storage: 1Gi
  requests:
    ephemeral-storage: 500Mi
```

Estimate your application's disk usage from logs, temporary files, and cache data. If your application writes large temporary files, consider using a PersistentVolumeClaim instead of ephemeral storage.

## Learn More

The kubelet evicts pods that exceed their ephemeral-storage limit. Use LimitRange to set default ephemeral-storage limits at the namespace level to catch containers that omit this setting.

**Affected resources:** kv-e2e-cluster-no-quota/Deployment/kv-e2e-unconstrained-app

</details>

<details>
<summary>Remediation: image-no-digest (1 resources affected)</summary>

## Why This Matters

Image tags are mutable pointers -- a registry administrator or attacker can re-push a different image under the same tag. Without a digest, you have no cryptographic guarantee that the image you deploy is the one you tested.

## How to Fix

Pin images by their SHA-256 content digest for a fully immutable reference:

```yaml
containers:
  - name: app
    image: nginx@sha256:a8281ce420348a01ea6e   # Immutable
```

Use `crane digest nginx:1.25.3` or `skopeo inspect` to resolve a tag to its digest during CI/CD, then commit the pinned reference.

## Learn More

SLSA Level 1+ and NIST SP 800-190 recommend digest pinning for container supply chain integrity. See the Kubernetes images documentation for details.

**Affected resources:** kv-e2e-cluster-no-quota/Deployment/kv-e2e-unconstrained-app

</details>

<details>
<summary>Remediation: liveness-readiness-probes (2 resources affected)</summary>

## Why This Matters

Without a liveness probe, Kubernetes cannot detect when a container has become unresponsive or deadlocked. The container continues running and consuming resources while failing to serve traffic. Users experience timeouts and errors until someone manually intervenes.

## How to Fix

Add a liveness probe that checks the container's health:

```yaml
containers:
  - name: app
    livenessProbe:
      httpGet:
        path: /healthz
        port: 8080
      initialDelaySeconds: 15
      periodSeconds: 10
      failureThreshold: 3
```

Use `httpGet` for HTTP services, `tcpSocket` for TCP services, or `exec` with a custom health check script for non-network workloads.

## Learn More

See the Kubernetes documentation on container probes. Set initialDelaySeconds high enough for your application to start, and consider adding a startupProbe for slow-starting containers.

**Affected resources:** kv-e2e-cluster-no-quota/Deployment/kv-e2e-unconstrained-app, kv-e2e-cluster-no-quota/Deployment/kv-e2e-unconstrained-app

</details>

<details>
<summary>Remediation: priority-class-missing (1 resources affected)</summary>

## Why This Matters

Without a PriorityClass, pods receive default priority (typically 0) and are among the first to be evicted during resource pressure or node maintenance. This means important application workloads may be killed before less critical ones, leading to unpredictable outages.

## How to Fix

Define PriorityClasses for your workloads and assign them appropriately:

```yaml
apiVersion: scheduling.k8s.io/v1
kind: PriorityClass
metadata:
  name: app-medium
value: 100000
---
# Reference in your workload:
spec:
  priorityClassName: app-medium
```

Create a tiered priority scheme (e.g., app-critical: 500000, app-medium: 100000, app-low: 10000) that reflects your workload importance hierarchy.

## Learn More

Refer to the Kubernetes Pod Priority and Preemption documentation. Establishing a consistent priority scheme across namespaces ensures predictable eviction behavior during resource contention.

**Affected resources:** kv-e2e-cluster-no-quota/Deployment/kv-e2e-unconstrained-app

</details>

<details>
<summary>Remediation: runtime-class (1 resources affected)</summary>

## Why This Matters

Without a RuntimeClass, pods use the default container runtime (typically runc), which shares the host kernel directly with containers. A kernel vulnerability can allow container escape to the host. Sandboxed runtimes like gVisor or Kata Containers add an additional isolation layer that intercepts system calls or runs containers in lightweight VMs.

## How to Fix

Specify a sandboxed RuntimeClass in the pod spec:

```yaml
spec:
  runtimeClassName: gvisor
```

Available RuntimeClasses depend on your cluster configuration. Common options include `gvisor` (user-space kernel), `kata` (micro-VMs), and `firecracker`. Check your cluster's available RuntimeClasses with `kubectl get runtimeclasses`.

## Learn More

Sandboxed runtimes are especially important for multi-tenant clusters and workloads processing untrusted input. They add latency overhead, so evaluate performance requirements. See the Kubernetes RuntimeClass documentation.

**Affected resources:** kv-e2e-cluster-no-quota/Deployment/kv-e2e-unconstrained-app

</details>

<details>
<summary>Remediation: topology-spread (1 resources affected)</summary>

## Why This Matters

Without topology spread constraints, the scheduler may place all replicas on the same node or in the same availability zone. If that node or zone fails, your entire service goes down despite having multiple replicas. This negates the high-availability benefits of running multiple pods.

## How to Fix

Add topology spread constraints to distribute replicas across failure domains:

```yaml
spec:
  topologySpreadConstraints:
    - maxSkew: 1
      topologyKey: kubernetes.io/hostname
      whenUnsatisfiable: DoNotSchedule
      labelSelector:
        matchLabels:
          app: my-app
    - maxSkew: 1
      topologyKey: topology.kubernetes.io/zone
      whenUnsatisfiable: ScheduleAnyway
```

Use `kubernetes.io/hostname` for node-level spreading and `topology.kubernetes.io/zone` for zone-level spreading.

## Learn More

See the Kubernetes Pod Topology Spread Constraints documentation. Combining hostname and zone constraints provides both node-level and zone-level fault tolerance.

**Affected resources:** kv-e2e-cluster-no-quota/Deployment/kv-e2e-unconstrained-app

</details>

### kv-e2e-cluster-proper (24 findings — 🟠5 🟡12 🔵7)

| Severity | Check | Resources | Message | Frameworks |
|----------|-------|-----------|---------|-----------|
| 🟠 High | network-policy-missing | kv-e2e-cluster-proper/Namespace/kv-e2e-cluster-proper | Namespace "kv-e2e-cluster-proper" has no NetworkPolicy defined. All pods are unrestricted. | CIS 5.3.2 · MITRE T1046 · NSA 4.1 · NSA 4.2 |
| 🟠 High | automount-token | kv-e2e-cluster-proper/Deployment/kv-e2e-proper-app | Deployment "kv-e2e-proper-app" auto-mounts a ServiceAccount token. Most workloads do not need Kubernetes API access. | CIS 5.1.6 · MITRE T1552.007 · NSA 3.2 |
| 🟠 High | default-service-account | kv-e2e-cluster-proper/Deployment/kv-e2e-proper-app | Deployment "kv-e2e-proper-app" uses the default ServiceAccount, which may have unintended permissions. | CIS 5.1.5 · CIS 5.1.6 · MITRE T1078.001 · NSA 3.1 · NSA 3.2 |
| 🟠 High | privilege-escalation | kv-e2e-cluster-proper/Deployment/kv-e2e-proper-app (pause) | Container "pause" does not set allowPrivilegeEscalation to false, permitting privilege escalation. | CIS 5.2.6 · MITRE T1068 · MITRE T1611 · NSA 1.1 · NSA 2.1 |
| 🟠 High | run-as-root | kv-e2e-cluster-proper/Deployment/kv-e2e-proper-app (pause) | Container "pause" does not set runAsNonRoot: true and may run as root. | CIS 5.2.7 · MITRE T1611 · NSA 1.1 |
| 🟡 Medium | network-policy-egress-unrestricted | kv-e2e-cluster-proper/Namespace/kv-e2e-cluster-proper | Namespace "kv-e2e-cluster-proper" has no NetworkPolicy with egress restrictions. Pods can reach any external destination. | CIS 5.3.2 · MITRE T1048 · NSA 4.2 |
| 🟡 Medium | psa-labels-missing | kv-e2e-cluster-proper/Namespace/kv-e2e-cluster-proper | Namespace "kv-e2e-cluster-proper" is missing the pod-security.kubernetes.io/enforce label; pod security is not enforced. | CIS 5.2.1 · MITRE T1610 · NSA 2.1 |
| 🟡 Medium | apparmor-profile | kv-e2e-cluster-proper/Deployment/kv-e2e-proper-app (pause) | Container "pause" does not have an AppArmor profile set. | CIS 5.6.3 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | capabilities-not-dropped | kv-e2e-cluster-proper/Deployment/kv-e2e-proper-app (pause) | Container "pause" does not drop ALL capabilities, leaving it with unnecessary default privileges. | CIS 5.2.8 · CIS 5.2.10 · MITRE T1068 · NSA 1.1 |
| 🟡 Medium | image-pull-policy | kv-e2e-cluster-proper/Deployment/kv-e2e-proper-app (pause) | Container "pause" uses a mutable image tag with pullPolicy "IfNotPresent" (image: registry.k8s.io/pause:3.9), risking stale images. | CIS 5.5.1 · MITRE T1525 · NSA 1.4 |
| 🟡 Medium | psa-restricted-violations | **3 resources** | Deployment "kv-e2e-proper-app" container "pause" violates PSS Restricted: runAsNonRoot is not true. | CIS 5.2.1 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | read-only-rootfs | kv-e2e-cluster-proper/Deployment/kv-e2e-proper-app (pause) | Container "pause" does not have a read-only root filesystem. | CIS 5.6.3 · MITRE T1565.001 · NSA 1.2 |
| 🟡 Medium | run-as-group | kv-e2e-cluster-proper/Deployment/kv-e2e-proper-app (pause) | Container "pause" does not set runAsGroup; the process will run as GID 0 (root group) by default. | CIS 5.2.7 · MITRE T1068 · NSA 1.1 |
| 🟡 Medium | seccomp-profile | kv-e2e-cluster-proper/Deployment/kv-e2e-proper-app (pause) | Container "pause" does not have a Seccomp profile set at either the container or pod level. | CIS 5.6.2 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | token-projection-config | kv-e2e-cluster-proper/Deployment/kv-e2e-proper-app | Deployment "kv-e2e-proper-app" does not use explicitly configured projected ServiceAccount tokens with expiry and audience restrictions. | CIS 5.1.6 · MITRE T1552.007 · NSA 3.2 |
| 🔵 Low | ephemeral-storage-limits | kv-e2e-cluster-proper/Deployment/kv-e2e-proper-app (pause) | Container "pause" is missing ephemeral-storage limits. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | image-no-digest | kv-e2e-cluster-proper/Deployment/kv-e2e-proper-app (pause) | Container "pause" image is not pinned by digest (image: registry.k8s.io/pause:3.9), allowing tag mutation. | CIS 5.5.1 · MITRE T1525 · NSA 1.4 |
| 🔵 Low | liveness-readiness-probes | **2 resources** | Container "pause" has no liveness probe configured. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | priority-class-missing | kv-e2e-cluster-proper/Deployment/kv-e2e-proper-app | Deployment "kv-e2e-proper-app" has no PriorityClass set; it will be evicted first during resource pressure. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | runtime-class | kv-e2e-cluster-proper/Deployment/kv-e2e-proper-app | Pod "kv-e2e-proper-app" does not specify a RuntimeClass, using the default (unsandboxed) runtime. | CIS 5.6.3 · MITRE T1611 · NSA 2.1 |
| 🔵 Low | topology-spread | kv-e2e-cluster-proper/Deployment/kv-e2e-proper-app | Deployment "kv-e2e-proper-app" has no topology spread constraints; all replicas may be scheduled on the same node. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |

<details>
<summary>psa-restricted-violations: 3 affected resources</summary>

- `kv-e2e-cluster-proper/Deployment/kv-e2e-proper-app (pause)`
- `kv-e2e-cluster-proper/Deployment/kv-e2e-proper-app (pause)`
- `kv-e2e-cluster-proper/Deployment/kv-e2e-proper-app (pause)`

</details>

<details>
<summary>liveness-readiness-probes: 2 affected resources</summary>

- `kv-e2e-cluster-proper/Deployment/kv-e2e-proper-app (pause)`
- `kv-e2e-cluster-proper/Deployment/kv-e2e-proper-app (pause)`

</details>

<details>
<summary>Remediation: network-policy-missing (1 resources affected)</summary>

## Why This Matters

Without NetworkPolicies, every pod in this namespace can communicate freely with every other pod in the cluster. If an attacker compromises a single pod, they can move laterally to databases, internal APIs, and other sensitive services with no network-level barriers.

## How to Fix

Create a default-deny NetworkPolicy for the namespace, then add targeted allow rules for legitimate traffic:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: my-namespace
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
```

After applying the default-deny, create additional NetworkPolicy resources that whitelist only the specific ingress and egress flows your workloads require.

## Learn More

See the Kubernetes documentation on NetworkPolicies and CIS Kubernetes Benchmark 5.3.2. A CNI plugin that supports NetworkPolicy (Calico, Cilium, Weave Net) must be installed for policies to take effect.

**Affected resources:** kv-e2e-cluster-proper/Namespace/kv-e2e-cluster-proper

</details>

<details>
<summary>Remediation: automount-token (1 resources affected)</summary>

## Why This Matters

When a ServiceAccount token is auto-mounted, every container in the pod can call the Kubernetes API. If a container is compromised through a vulnerability or misconfiguration, the attacker gains API access to enumerate resources, read secrets, or escalate privileges.

## How to Fix

Disable auto-mounting at the pod spec level for workloads that do not need API access:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      automountServiceAccountToken: false
      containers:
        - name: app
          image: my-app:latest
```

For workloads that do require API access, use projected tokens with bounded lifetime and audience restrictions instead of the default long-lived token.

## Learn More

Refer to the Kubernetes documentation on configuring service accounts for pods and CIS Kubernetes Benchmark 5.1.6 for auto-mount token guidance.

**Affected resources:** kv-e2e-cluster-proper/Deployment/kv-e2e-proper-app

</details>

<details>
<summary>Remediation: default-service-account (1 resources affected)</summary>

## Why This Matters

The default ServiceAccount is shared by every pod in a namespace. If any pod is compromised, the attacker inherits whatever permissions have been granted to the default account via role bindings, enabling lateral movement across all workloads sharing it.

## How to Fix

Create a dedicated ServiceAccount for each workload and reference it in the pod spec:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-app
  namespace: production
automountServiceAccountToken: false
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      serviceAccountName: my-app
```

Grant only the permissions the workload actually needs via a dedicated Role and RoleBinding.

## Learn More

See the Kubernetes documentation on managing service accounts and CIS Kubernetes Benchmark 5.1.5 for guidance on ensuring default service accounts are not actively used.

**Affected resources:** kv-e2e-cluster-proper/Deployment/kv-e2e-proper-app

</details>

<details>
<summary>Remediation: privilege-escalation (1 resources affected)</summary>

## Why This Matters

By default, Kubernetes allows containers to escalate privileges via setuid/setgid binaries, which let a process gain more permissions than its parent. An attacker can exploit this using setuid binaries already present in the container image (like `su`, `sudo`, or `ping`) to elevate from a low-privilege user to root.

## How to Fix

Explicitly disable privilege escalation in the container's securityContext:

```yaml
securityContext:
  allowPrivilegeEscalation: false
  runAsNonRoot: true
  capabilities:
    drop: ["ALL"]
```

This blocks the use of setuid/setgid binaries and prevents the no_new_privs Linux flag from being cleared. The vast majority of application containers do not need privilege escalation.

## Learn More

This is required by the Pod Security Standards "Restricted" profile and CIS Benchmark 5.2.5. Disabling privilege escalation is one of the most impactful single-line security improvements you can make.

**Affected resources:** kv-e2e-cluster-proper/Deployment/kv-e2e-proper-app

</details>

<details>
<summary>Remediation: run-as-root (1 resources affected)</summary>

## Why This Matters

Without `runAsNonRoot: true`, Kubernetes does not enforce non-root execution and the container may default to running as UID 0 depending on the image's USER directive. If the image defaults to root, the container process gains full privileges, increasing the blast radius of any compromise or container escape.

## How to Fix

Enforce non-root execution in the securityContext:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
```

With `runAsNonRoot: true`, Kubernetes will reject the pod at admission time if the container image attempts to run as root. Setting an explicit `runAsUser` provides an additional guarantee.

## Learn More

This aligns with CIS Benchmark 5.2.6 and the Pod Security Standards "Restricted" profile. The `runAsNonRoot` field acts as a safety net even when images change their default USER.

**Affected resources:** kv-e2e-cluster-proper/Deployment/kv-e2e-proper-app

</details>

<details>
<summary>Remediation: network-policy-egress-unrestricted (1 resources affected)</summary>

## Why This Matters

Without any egress NetworkPolicy in this namespace, pods can freely send traffic to any destination including the public internet. A compromised pod can exfiltrate sensitive data, reach cloud metadata services (e.g., 169.254.169.254), or establish reverse shells to attacker-controlled servers.

## How to Fix

Create a NetworkPolicy with `Egress` in `policyTypes` to restrict outbound traffic. At minimum, allow DNS resolution:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-egress
  namespace: my-namespace
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector: {}
      ports:
        - port: 53
          protocol: UDP
```

Add additional egress rules for specific services your workloads need to reach.

## Learn More

See the Kubernetes NetworkPolicy documentation and CIS Kubernetes Benchmark 5.3.2. Egress controls are a key defense-in-depth measure recommended by the NSA/CISA Kubernetes Hardening Guide.

**Affected resources:** kv-e2e-cluster-proper/Namespace/kv-e2e-cluster-proper

</details>

<details>
<summary>Remediation: psa-labels-missing (1 resources affected)</summary>

## Why This Matters

Without PSA enforcement labels, any pod configuration is allowed in this namespace, including privileged containers, host namespace access, and root execution. This bypasses Kubernetes' built-in Pod Security Standards and leaves the namespace vulnerable to workloads that could compromise the node.

## How to Fix

Add Pod Security Admission labels to enforce a security profile on all pods in the namespace:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: kv-e2e-cluster-proper
  labels:
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

Start with `baseline` enforcement to block known privilege escalations, then upgrade to `restricted` after verifying all workloads are compliant.

## Learn More

See the Kubernetes Pod Security Admission documentation and CIS Kubernetes Benchmark 5.2. The three-tier approach (enforce, audit, warn) allows gradual adoption of stricter profiles.

**Affected resources:** kv-e2e-cluster-proper/Namespace/kv-e2e-cluster-proper

</details>

<details>
<summary>Remediation: apparmor-profile (1 resources affected)</summary>

## Why This Matters

AppArmor provides mandatory access control (MAC) that restricts which files, network resources, and capabilities a container process can access. Without an AppArmor profile, the container operates without these restrictions, allowing an attacker with code execution to access any file the container user can read and make unrestricted network connections.

## How to Fix

Apply an AppArmor profile in the container's securityContext (Kubernetes 1.30+):

```yaml
securityContext:
  appArmorProfile:
    type: RuntimeDefault
```

The RuntimeDefault profile provides sensible restrictions for most applications. For tighter control, create a custom Localhost profile that only allows the specific file and network access your application needs.

## Learn More

AppArmor is available on Debian/Ubuntu-based nodes. RHEL/CentOS nodes use SELinux instead. Both provide MAC enforcement. Refer to CIS Benchmark 5.7.5 and the Kubernetes AppArmor documentation.

**Affected resources:** kv-e2e-cluster-proper/Deployment/kv-e2e-proper-app

</details>

<details>
<summary>Remediation: capabilities-not-dropped (1 resources affected)</summary>

## Why This Matters

By default, containers receive a set of Linux capabilities including KILL, SETUID, SETGID, and NET_RAW. These defaults are rarely needed by application code and significantly increase the potential damage from a container compromise. Dropping all capabilities follows the principle of least privilege.

## How to Fix

Explicitly drop all capabilities and selectively add back only what your application needs:

```yaml
securityContext:
  capabilities:
    drop: ["ALL"]
    add: ["NET_BIND_SERVICE"]  # Only if needed
```

Most web applications, API servers, and background workers run perfectly with all capabilities dropped. Test your application after making this change to confirm no functionality is lost.

## Learn More

This is required by the Pod Security Standards "Restricted" profile and aligns with CIS Benchmark 5.2.7. Kubernetes best practice is to treat capability grants as exceptions that require explicit justification.

**Affected resources:** kv-e2e-cluster-proper/Deployment/kv-e2e-proper-app

</details>

<details>
<summary>Remediation: image-pull-policy (1 resources affected)</summary>

## Why This Matters

When a mutable image tag is used without `imagePullPolicy: Always`, Kubernetes may serve a cached version of the image from the node. If the tag has been updated in the registry (with a security patch or -- worse -- a compromised layer), the running container will not reflect those changes.

## How to Fix

Set `imagePullPolicy: Always` for any container using a mutable tag:

```yaml
containers:
  - name: app
    image: nginx:1.25.3
    imagePullPolicy: Always   # Forces fresh pull each time
```

Alternatively, pin images by digest (`image@sha256:...`), which makes the pull policy irrelevant because the content is immutable.

## Learn More

See the Kubernetes documentation on image pull policies and CIS Kubernetes Benchmark 5.4.2 for pull policy guidance.

**Affected resources:** kv-e2e-cluster-proper/Deployment/kv-e2e-proper-app

</details>

<details>
<summary>Remediation: psa-restricted-violations (3 resources affected)</summary>

## Why This Matters

Running as root inside a container means that any container escape vulnerability immediately grants root access on the host node. Even without an escape, root inside the container can modify sensitive files, install packages, and access capabilities that non-root users cannot.

## How to Fix

Set `runAsNonRoot: true` and specify a non-root user ID in the security context:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
```

Set this at the pod level to apply to all containers. Ensure your container image supports running as a non-root user (many official images do).

## Learn More

See the Pod Security Standards Restricted profile and CIS Kubernetes Benchmark 5.2.6. Running as non-root is a fundamental container security best practice.

**Affected resources:** kv-e2e-cluster-proper/Deployment/kv-e2e-proper-app, kv-e2e-cluster-proper/Deployment/kv-e2e-proper-app, kv-e2e-cluster-proper/Deployment/kv-e2e-proper-app

</details>

<details>
<summary>Remediation: read-only-rootfs (1 resources affected)</summary>

## Why This Matters

A writable root filesystem allows an attacker who gains code execution in your container to modify application binaries, install attack tools, plant backdoors, or persist malware across container restarts. Making the filesystem read-only eliminates an entire class of post-exploitation techniques.

## How to Fix

Enable a read-only root filesystem and mount writable volumes only where needed:

```yaml
securityContext:
  readOnlyRootFilesystem: true
volumeMounts:
  - name: tmp
    mountPath: /tmp
volumes:
  - name: tmp
    emptyDir: {}
```

Common paths that need write access include /tmp, /var/cache, and /var/run. Mount each as an emptyDir or tmpfs volume rather than making the entire filesystem writable.

## Learn More

This aligns with CIS Benchmark 5.2.4 and the defense-in-depth principle. Combined with dropping capabilities and running as non-root, a read-only filesystem forms a strong container hardening baseline.

**Affected resources:** kv-e2e-cluster-proper/Deployment/kv-e2e-proper-app

</details>

<details>
<summary>Remediation: run-as-group (1 resources affected)</summary>

## Why This Matters

Without an explicit runAsGroup, the container process defaults to GID 0 (the root group). Files and sockets owned by the root group become accessible to the container, including potentially sensitive host files if volumes are mounted. This widens the attack surface unnecessarily.

## How to Fix

Set an explicit non-root group in the securityContext:

```yaml
securityContext:
  runAsGroup: 1000
  runAsUser: 1000
  runAsNonRoot: true
```

Ensure the container image's application files and directories are readable by the specified GID. You may need to adjust file ownership in your Dockerfile with `chown`.

## Learn More

This aligns with CIS Benchmark 5.2.6 and the Pod Security Standards "Restricted" profile. Always set runAsUser, runAsGroup, and runAsNonRoot together for comprehensive identity control.

**Affected resources:** kv-e2e-cluster-proper/Deployment/kv-e2e-proper-app

</details>

<details>
<summary>Remediation: seccomp-profile (1 resources affected)</summary>

## Why This Matters

Without a Seccomp profile, containers can invoke any of the 300+ Linux system calls, leaving the entire kernel attack surface exposed. Kernel vulnerabilities in obscure syscalls are a primary vector for container escapes. Seccomp filtering blocks dangerous syscalls that legitimate applications never use.

## How to Fix

Apply a Seccomp profile at the container or pod level:

```yaml
securityContext:
  seccompProfile:
    type: RuntimeDefault
```

The RuntimeDefault profile blocks approximately 50 dangerous syscalls while allowing normal application behavior. For stricter controls, use a custom Localhost profile tailored to your application's needs. Set the profile at the pod level to apply it to all containers.

## Learn More

Seccomp profiles are required by the Pod Security Standards "Restricted" profile and CIS Benchmark 5.7.2. Use tools like `strace` or the Security Profiles Operator to generate custom profiles for your workloads.

**Affected resources:** kv-e2e-cluster-proper/Deployment/kv-e2e-proper-app

</details>

<details>
<summary>Remediation: token-projection-config (1 resources affected)</summary>

## Why This Matters

Without explicit projection configuration, ServiceAccount tokens use Kubernetes defaults: no audience restriction and a long expiration. A stolen token remains valid for an extended period and can be used against any API server endpoint, widening the blast radius of a compromise.

## How to Fix

Add a projected volume with explicit expiration and audience:

```yaml
spec:
  volumes:
    - name: token
      projected:
        sources:
          - serviceAccountToken:
              expirationSeconds: 3600
              audience: my-api
              path: token
  containers:
    - name: app
      volumeMounts:
        - name: token
          mountPath: /var/run/secrets/tokens
          readOnly: true
```

Projected tokens auto-rotate before expiry and are rejected by endpoints outside the specified audience.

## Learn More

See the Kubernetes documentation on projected volumes and service account token volume projection for detailed configuration options.

**Affected resources:** kv-e2e-cluster-proper/Deployment/kv-e2e-proper-app

</details>

<details>
<summary>Remediation: ephemeral-storage-limits (1 resources affected)</summary>

## Why This Matters

Ephemeral storage includes container logs, emptyDir volumes, and the writable container layer. Without limits, a single container can fill the node's root disk, triggering eviction of all pods on that node and potentially causing a cascading failure across your cluster. This is a common denial-of-service vector.

## How to Fix

Set ephemeral-storage limits alongside your CPU and memory limits:

```yaml
resources:
  limits:
    ephemeral-storage: 1Gi
  requests:
    ephemeral-storage: 500Mi
```

Estimate your application's disk usage from logs, temporary files, and cache data. If your application writes large temporary files, consider using a PersistentVolumeClaim instead of ephemeral storage.

## Learn More

The kubelet evicts pods that exceed their ephemeral-storage limit. Use LimitRange to set default ephemeral-storage limits at the namespace level to catch containers that omit this setting.

**Affected resources:** kv-e2e-cluster-proper/Deployment/kv-e2e-proper-app

</details>

<details>
<summary>Remediation: image-no-digest (1 resources affected)</summary>

## Why This Matters

Image tags are mutable pointers -- a registry administrator or attacker can re-push a different image under the same tag. Without a digest, you have no cryptographic guarantee that the image you deploy is the one you tested.

## How to Fix

Pin images by their SHA-256 content digest for a fully immutable reference:

```yaml
containers:
  - name: app
    image: nginx@sha256:a8281ce420348a01ea6e   # Immutable
```

Use `crane digest nginx:1.25.3` or `skopeo inspect` to resolve a tag to its digest during CI/CD, then commit the pinned reference.

## Learn More

SLSA Level 1+ and NIST SP 800-190 recommend digest pinning for container supply chain integrity. See the Kubernetes images documentation for details.

**Affected resources:** kv-e2e-cluster-proper/Deployment/kv-e2e-proper-app

</details>

<details>
<summary>Remediation: liveness-readiness-probes (2 resources affected)</summary>

## Why This Matters

Without a liveness probe, Kubernetes cannot detect when a container has become unresponsive or deadlocked. The container continues running and consuming resources while failing to serve traffic. Users experience timeouts and errors until someone manually intervenes.

## How to Fix

Add a liveness probe that checks the container's health:

```yaml
containers:
  - name: app
    livenessProbe:
      httpGet:
        path: /healthz
        port: 8080
      initialDelaySeconds: 15
      periodSeconds: 10
      failureThreshold: 3
```

Use `httpGet` for HTTP services, `tcpSocket` for TCP services, or `exec` with a custom health check script for non-network workloads.

## Learn More

See the Kubernetes documentation on container probes. Set initialDelaySeconds high enough for your application to start, and consider adding a startupProbe for slow-starting containers.

**Affected resources:** kv-e2e-cluster-proper/Deployment/kv-e2e-proper-app, kv-e2e-cluster-proper/Deployment/kv-e2e-proper-app

</details>

<details>
<summary>Remediation: priority-class-missing (1 resources affected)</summary>

## Why This Matters

Without a PriorityClass, pods receive default priority (typically 0) and are among the first to be evicted during resource pressure or node maintenance. This means important application workloads may be killed before less critical ones, leading to unpredictable outages.

## How to Fix

Define PriorityClasses for your workloads and assign them appropriately:

```yaml
apiVersion: scheduling.k8s.io/v1
kind: PriorityClass
metadata:
  name: app-medium
value: 100000
---
# Reference in your workload:
spec:
  priorityClassName: app-medium
```

Create a tiered priority scheme (e.g., app-critical: 500000, app-medium: 100000, app-low: 10000) that reflects your workload importance hierarchy.

## Learn More

Refer to the Kubernetes Pod Priority and Preemption documentation. Establishing a consistent priority scheme across namespaces ensures predictable eviction behavior during resource contention.

**Affected resources:** kv-e2e-cluster-proper/Deployment/kv-e2e-proper-app

</details>

<details>
<summary>Remediation: runtime-class (1 resources affected)</summary>

## Why This Matters

Without a RuntimeClass, pods use the default container runtime (typically runc), which shares the host kernel directly with containers. A kernel vulnerability can allow container escape to the host. Sandboxed runtimes like gVisor or Kata Containers add an additional isolation layer that intercepts system calls or runs containers in lightweight VMs.

## How to Fix

Specify a sandboxed RuntimeClass in the pod spec:

```yaml
spec:
  runtimeClassName: gvisor
```

Available RuntimeClasses depend on your cluster configuration. Common options include `gvisor` (user-space kernel), `kata` (micro-VMs), and `firecracker`. Check your cluster's available RuntimeClasses with `kubectl get runtimeclasses`.

## Learn More

Sandboxed runtimes are especially important for multi-tenant clusters and workloads processing untrusted input. They add latency overhead, so evaluate performance requirements. See the Kubernetes RuntimeClass documentation.

**Affected resources:** kv-e2e-cluster-proper/Deployment/kv-e2e-proper-app

</details>

<details>
<summary>Remediation: topology-spread (1 resources affected)</summary>

## Why This Matters

Without topology spread constraints, the scheduler may place all replicas on the same node or in the same availability zone. If that node or zone fails, your entire service goes down despite having multiple replicas. This negates the high-availability benefits of running multiple pods.

## How to Fix

Add topology spread constraints to distribute replicas across failure domains:

```yaml
spec:
  topologySpreadConstraints:
    - maxSkew: 1
      topologyKey: kubernetes.io/hostname
      whenUnsatisfiable: DoNotSchedule
      labelSelector:
        matchLabels:
          app: my-app
    - maxSkew: 1
      topologyKey: topology.kubernetes.io/zone
      whenUnsatisfiable: ScheduleAnyway
```

Use `kubernetes.io/hostname` for node-level spreading and `topology.kubernetes.io/zone` for zone-level spreading.

## Learn More

See the Kubernetes Pod Topology Spread Constraints documentation. Combining hostname and zone constraints provides both node-level and zone-level fault tolerance.

**Affected resources:** kv-e2e-cluster-proper/Deployment/kv-e2e-proper-app

</details>

### kv-e2e-image (284 findings — 🟠43 🟡164 🔵77)

| Severity | Check | Resources | Message | Frameworks |
|----------|-------|-----------|---------|-----------|
| 🟠 High | automount-token | **5 resources** | Deployment "disallowed-registry-demo" auto-mounts a ServiceAccount token. Most workloads do not need Kubernetes API access. | CIS 5.1.6 · MITRE T1552.007 · NSA 3.2 |
| 🟠 High | default-service-account | **5 resources** | Deployment "disallowed-registry-demo" uses the default ServiceAccount, which may have unintended permissions. | CIS 5.1.5 · CIS 5.1.6 · MITRE T1078.001 · NSA 3.1 · NSA 3.2 |
| 🟠 High | privilege-escalation | **16 resources** | Container "untrusted-app" does not set allowPrivilegeEscalation to false, permitting privilege escalation. | CIS 5.2.6 · MITRE T1068 · MITRE T1611 · NSA 1.1 · NSA 2.1 |
| 🟠 High | run-as-root | **16 resources** | Container "untrusted-app" does not set runAsNonRoot: true and may run as root. | CIS 5.2.7 · MITRE T1611 · NSA 1.1 |
| 🟠 High | network-policy-missing | kv-e2e-image/Namespace/kv-e2e-image | Namespace "kv-e2e-image" has no NetworkPolicy defined. All pods are unrestricted. | CIS 5.3.2 · MITRE T1046 · NSA 4.1 · NSA 4.2 |
| 🟡 Medium | apparmor-profile | **16 resources** | Container "untrusted-app" does not have an AppArmor profile set. | CIS 5.6.3 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | capabilities-not-dropped | **16 resources** | Container "untrusted-app" does not drop ALL capabilities, leaving it with unnecessary default privileges. | CIS 5.2.8 · CIS 5.2.10 · MITRE T1068 · NSA 1.1 |
| 🟡 Medium | image-pull-policy | **6 resources** | Container "untrusted-app" uses a mutable image tag with pullPolicy "IfNotPresent" (image: some-untrusted-registry.io/app:v1), risking stale images. | CIS 5.5.1 · MITRE T1525 · NSA 1.4 |
| 🟡 Medium | psa-restricted-violations | **48 resources** | Deployment "disallowed-registry-demo" container "untrusted-app" violates PSS Restricted: runAsNonRoot is not true. | CIS 5.2.1 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | read-only-rootfs | **16 resources** | Container "untrusted-app" does not have a read-only root filesystem. | CIS 5.6.3 · MITRE T1565.001 · NSA 1.2 |
| 🟡 Medium | resource-requests-missing | **16 resources** | Container "untrusted-app" is missing both CPU and memory requests. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🟡 Medium | run-as-group | **16 resources** | Container "untrusted-app" does not set runAsGroup; the process will run as GID 0 (root group) by default. | CIS 5.2.7 · MITRE T1068 · NSA 1.1 |
| 🟡 Medium | seccomp-profile | **16 resources** | Container "untrusted-app" does not have a Seccomp profile set at either the container or pod level. | CIS 5.6.2 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | token-projection-config | **5 resources** | Deployment "disallowed-registry-demo" does not use explicitly configured projected ServiceAccount tokens with expiry and audience restrictions. | CIS 5.1.6 · MITRE T1552.007 · NSA 3.2 |
| 🟡 Medium | network-policy-egress-unrestricted | kv-e2e-image/Namespace/kv-e2e-image | Namespace "kv-e2e-image" has no NetworkPolicy with egress restrictions. Pods can reach any external destination. | CIS 5.3.2 · MITRE T1048 · NSA 4.2 |
| 🟡 Medium | psa-labels-missing | kv-e2e-image/Namespace/kv-e2e-image | Namespace "kv-e2e-image" is missing the pod-security.kubernetes.io/enforce label; pod security is not enforced. | CIS 5.2.1 · MITRE T1610 · NSA 2.1 |
| 🟡 Medium | image-tag-latest | **5 resources** | Container "explicit-latest" uses the :latest tag (image: nginx:latest), which can lead to unpredictable deployments. | CIS 5.5.1 · MITRE T1525 · NSA 1.4 |
| 🟡 Medium | image-tag-missing | **2 resources** | Container "implicit-latest" has no image tag or digest (image: busybox), making deployments completely non-deterministic. | CIS 5.5.1 · MITRE T1525 · NSA 1.4 |
| 🔵 Low | ephemeral-storage-limits | **16 resources** | Container "untrusted-app" is missing ephemeral-storage limits. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | image-no-digest | **16 resources** | Container "untrusted-app" image is not pinned by digest (image: some-untrusted-registry.io/app:v1), allowing tag mutation. | CIS 5.5.1 · MITRE T1525 · NSA 1.4 |
| 🔵 Low | liveness-readiness-probes | **28 resources** | Container "untrusted-app" has no liveness probe configured. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | priority-class-missing | **5 resources** | Deployment "disallowed-registry-demo" has no PriorityClass set; it will be evicted first during resource pressure. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | runtime-class | **5 resources** | Pod "disallowed-registry-demo" does not specify a RuntimeClass, using the default (unsandboxed) runtime. | CIS 5.6.3 · MITRE T1611 · NSA 2.1 |
| 🔵 Low | topology-spread | **5 resources** | Deployment "disallowed-registry-demo" has no topology spread constraints; all replicas may be scheduled on the same node. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | limit-range-missing | kv-e2e-image/Namespace/kv-e2e-image | Namespace "kv-e2e-image" has no LimitRange defined. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | resource-quota-missing | kv-e2e-image/Namespace/kv-e2e-image | Namespace "kv-e2e-image" has no ResourceQuota defined. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |

<details>
<summary>automount-token: 5 affected resources</summary>

- `kv-e2e-image/Deployment/disallowed-registry-demo`
- `kv-e2e-image/Deployment/latest-tag-demo`
- `kv-e2e-image/Deployment/mixed-images-demo`
- `kv-e2e-image/Deployment/no-digest-demo`
- `kv-e2e-image/Deployment/pull-policy-demo`

</details>

<details>
<summary>default-service-account: 5 affected resources</summary>

- `kv-e2e-image/Deployment/disallowed-registry-demo`
- `kv-e2e-image/Deployment/latest-tag-demo`
- `kv-e2e-image/Deployment/mixed-images-demo`
- `kv-e2e-image/Deployment/no-digest-demo`
- `kv-e2e-image/Deployment/pull-policy-demo`

</details>

<details>
<summary>privilege-escalation: 16 affected resources</summary>

- `kv-e2e-image/Deployment/disallowed-registry-demo (untrusted-app)`
- `kv-e2e-image/Deployment/disallowed-registry-demo (another-unknown)`
- `kv-e2e-image/Deployment/disallowed-registry-demo (trusted-pause)`
- `kv-e2e-image/Deployment/latest-tag-demo (explicit-latest)`
- `kv-e2e-image/Deployment/latest-tag-demo (implicit-latest)`
- `kv-e2e-image/Deployment/mixed-images-demo (app-mutable)`
- `kv-e2e-image/Deployment/mixed-images-demo (app-safe-tag)`
- `kv-e2e-image/Deployment/mixed-images-demo (init-no-tag)`
- `kv-e2e-image/Deployment/mixed-images-demo (sidecar-latest)`
- `kv-e2e-image/Deployment/mixed-images-demo (init-versioned)`
- `kv-e2e-image/Deployment/no-digest-demo (tag-only)`
- `kv-e2e-image/Deployment/no-digest-demo (tag-pinned)`
- `kv-e2e-image/Deployment/pull-policy-demo (mutable-ifnotpresent)`
- `kv-e2e-image/Deployment/pull-policy-demo (mutable-default)`
- `kv-e2e-image/Deployment/pull-policy-demo (safe-always)`
- `kv-e2e-image/Deployment/pull-policy-demo (latest-default)`

</details>

<details>
<summary>run-as-root: 16 affected resources</summary>

- `kv-e2e-image/Deployment/disallowed-registry-demo (untrusted-app)`
- `kv-e2e-image/Deployment/disallowed-registry-demo (another-unknown)`
- `kv-e2e-image/Deployment/disallowed-registry-demo (trusted-pause)`
- `kv-e2e-image/Deployment/latest-tag-demo (explicit-latest)`
- `kv-e2e-image/Deployment/latest-tag-demo (implicit-latest)`
- `kv-e2e-image/Deployment/mixed-images-demo (app-mutable)`
- `kv-e2e-image/Deployment/mixed-images-demo (app-safe-tag)`
- `kv-e2e-image/Deployment/mixed-images-demo (init-no-tag)`
- `kv-e2e-image/Deployment/mixed-images-demo (sidecar-latest)`
- `kv-e2e-image/Deployment/mixed-images-demo (init-versioned)`
- `kv-e2e-image/Deployment/no-digest-demo (tag-only)`
- `kv-e2e-image/Deployment/no-digest-demo (tag-pinned)`
- `kv-e2e-image/Deployment/pull-policy-demo (mutable-ifnotpresent)`
- `kv-e2e-image/Deployment/pull-policy-demo (mutable-default)`
- `kv-e2e-image/Deployment/pull-policy-demo (safe-always)`
- `kv-e2e-image/Deployment/pull-policy-demo (latest-default)`

</details>

<details>
<summary>apparmor-profile: 16 affected resources</summary>

- `kv-e2e-image/Deployment/disallowed-registry-demo (untrusted-app)`
- `kv-e2e-image/Deployment/disallowed-registry-demo (another-unknown)`
- `kv-e2e-image/Deployment/disallowed-registry-demo (trusted-pause)`
- `kv-e2e-image/Deployment/latest-tag-demo (explicit-latest)`
- `kv-e2e-image/Deployment/latest-tag-demo (implicit-latest)`
- `kv-e2e-image/Deployment/mixed-images-demo (app-mutable)`
- `kv-e2e-image/Deployment/mixed-images-demo (app-safe-tag)`
- `kv-e2e-image/Deployment/mixed-images-demo (init-no-tag)`
- `kv-e2e-image/Deployment/mixed-images-demo (sidecar-latest)`
- `kv-e2e-image/Deployment/mixed-images-demo (init-versioned)`
- `kv-e2e-image/Deployment/no-digest-demo (tag-only)`
- `kv-e2e-image/Deployment/no-digest-demo (tag-pinned)`
- `kv-e2e-image/Deployment/pull-policy-demo (mutable-ifnotpresent)`
- `kv-e2e-image/Deployment/pull-policy-demo (mutable-default)`
- `kv-e2e-image/Deployment/pull-policy-demo (safe-always)`
- `kv-e2e-image/Deployment/pull-policy-demo (latest-default)`

</details>

<details>
<summary>capabilities-not-dropped: 16 affected resources</summary>

- `kv-e2e-image/Deployment/disallowed-registry-demo (untrusted-app)`
- `kv-e2e-image/Deployment/disallowed-registry-demo (another-unknown)`
- `kv-e2e-image/Deployment/disallowed-registry-demo (trusted-pause)`
- `kv-e2e-image/Deployment/latest-tag-demo (explicit-latest)`
- `kv-e2e-image/Deployment/latest-tag-demo (implicit-latest)`
- `kv-e2e-image/Deployment/mixed-images-demo (app-mutable)`
- `kv-e2e-image/Deployment/mixed-images-demo (app-safe-tag)`
- `kv-e2e-image/Deployment/mixed-images-demo (init-no-tag)`
- `kv-e2e-image/Deployment/mixed-images-demo (sidecar-latest)`
- `kv-e2e-image/Deployment/mixed-images-demo (init-versioned)`
- `kv-e2e-image/Deployment/no-digest-demo (tag-only)`
- `kv-e2e-image/Deployment/no-digest-demo (tag-pinned)`
- `kv-e2e-image/Deployment/pull-policy-demo (mutable-ifnotpresent)`
- `kv-e2e-image/Deployment/pull-policy-demo (mutable-default)`
- `kv-e2e-image/Deployment/pull-policy-demo (safe-always)`
- `kv-e2e-image/Deployment/pull-policy-demo (latest-default)`

</details>

<details>
<summary>image-pull-policy: 6 affected resources</summary>

- `kv-e2e-image/Deployment/disallowed-registry-demo (untrusted-app)`
- `kv-e2e-image/Deployment/disallowed-registry-demo (another-unknown)`
- `kv-e2e-image/Deployment/disallowed-registry-demo (trusted-pause)`
- `kv-e2e-image/Deployment/mixed-images-demo (app-mutable)`
- `kv-e2e-image/Deployment/pull-policy-demo (mutable-ifnotpresent)`
- `kv-e2e-image/Deployment/pull-policy-demo (mutable-default)`

</details>

<details>
<summary>psa-restricted-violations: 48 affected resources</summary>

- `kv-e2e-image/Deployment/disallowed-registry-demo (untrusted-app)`
- `kv-e2e-image/Deployment/disallowed-registry-demo (untrusted-app)`
- `kv-e2e-image/Deployment/disallowed-registry-demo (untrusted-app)`
- `kv-e2e-image/Deployment/disallowed-registry-demo (another-unknown)`
- `kv-e2e-image/Deployment/disallowed-registry-demo (another-unknown)`
- `kv-e2e-image/Deployment/disallowed-registry-demo (another-unknown)`
- `kv-e2e-image/Deployment/disallowed-registry-demo (trusted-pause)`
- `kv-e2e-image/Deployment/disallowed-registry-demo (trusted-pause)`
- `kv-e2e-image/Deployment/disallowed-registry-demo (trusted-pause)`
- `kv-e2e-image/Deployment/latest-tag-demo (explicit-latest)`
- `kv-e2e-image/Deployment/latest-tag-demo (explicit-latest)`
- `kv-e2e-image/Deployment/latest-tag-demo (explicit-latest)`
- `kv-e2e-image/Deployment/latest-tag-demo (implicit-latest)`
- `kv-e2e-image/Deployment/latest-tag-demo (implicit-latest)`
- `kv-e2e-image/Deployment/latest-tag-demo (implicit-latest)`
- `kv-e2e-image/Deployment/mixed-images-demo (app-mutable)`
- `kv-e2e-image/Deployment/mixed-images-demo (app-mutable)`
- `kv-e2e-image/Deployment/mixed-images-demo (app-mutable)`
- `kv-e2e-image/Deployment/mixed-images-demo (app-safe-tag)`
- `kv-e2e-image/Deployment/mixed-images-demo (app-safe-tag)`
- `kv-e2e-image/Deployment/mixed-images-demo (app-safe-tag)`
- `kv-e2e-image/Deployment/mixed-images-demo (init-no-tag)`
- `kv-e2e-image/Deployment/mixed-images-demo (init-no-tag)`
- `kv-e2e-image/Deployment/mixed-images-demo (init-no-tag)`
- `kv-e2e-image/Deployment/mixed-images-demo (sidecar-latest)`
- `kv-e2e-image/Deployment/mixed-images-demo (sidecar-latest)`
- `kv-e2e-image/Deployment/mixed-images-demo (sidecar-latest)`
- `kv-e2e-image/Deployment/mixed-images-demo (init-versioned)`
- `kv-e2e-image/Deployment/mixed-images-demo (init-versioned)`
- `kv-e2e-image/Deployment/mixed-images-demo (init-versioned)`
- `kv-e2e-image/Deployment/no-digest-demo (tag-only)`
- `kv-e2e-image/Deployment/no-digest-demo (tag-only)`
- `kv-e2e-image/Deployment/no-digest-demo (tag-only)`
- `kv-e2e-image/Deployment/no-digest-demo (tag-pinned)`
- `kv-e2e-image/Deployment/no-digest-demo (tag-pinned)`
- `kv-e2e-image/Deployment/no-digest-demo (tag-pinned)`
- `kv-e2e-image/Deployment/pull-policy-demo (mutable-ifnotpresent)`
- `kv-e2e-image/Deployment/pull-policy-demo (mutable-ifnotpresent)`
- `kv-e2e-image/Deployment/pull-policy-demo (mutable-ifnotpresent)`
- `kv-e2e-image/Deployment/pull-policy-demo (mutable-default)`
- `kv-e2e-image/Deployment/pull-policy-demo (mutable-default)`
- `kv-e2e-image/Deployment/pull-policy-demo (mutable-default)`
- `kv-e2e-image/Deployment/pull-policy-demo (safe-always)`
- `kv-e2e-image/Deployment/pull-policy-demo (safe-always)`
- `kv-e2e-image/Deployment/pull-policy-demo (safe-always)`
- `kv-e2e-image/Deployment/pull-policy-demo (latest-default)`
- `kv-e2e-image/Deployment/pull-policy-demo (latest-default)`
- `kv-e2e-image/Deployment/pull-policy-demo (latest-default)`

</details>

<details>
<summary>read-only-rootfs: 16 affected resources</summary>

- `kv-e2e-image/Deployment/disallowed-registry-demo (untrusted-app)`
- `kv-e2e-image/Deployment/disallowed-registry-demo (another-unknown)`
- `kv-e2e-image/Deployment/disallowed-registry-demo (trusted-pause)`
- `kv-e2e-image/Deployment/latest-tag-demo (explicit-latest)`
- `kv-e2e-image/Deployment/latest-tag-demo (implicit-latest)`
- `kv-e2e-image/Deployment/mixed-images-demo (app-mutable)`
- `kv-e2e-image/Deployment/mixed-images-demo (app-safe-tag)`
- `kv-e2e-image/Deployment/mixed-images-demo (init-no-tag)`
- `kv-e2e-image/Deployment/mixed-images-demo (sidecar-latest)`
- `kv-e2e-image/Deployment/mixed-images-demo (init-versioned)`
- `kv-e2e-image/Deployment/no-digest-demo (tag-only)`
- `kv-e2e-image/Deployment/no-digest-demo (tag-pinned)`
- `kv-e2e-image/Deployment/pull-policy-demo (mutable-ifnotpresent)`
- `kv-e2e-image/Deployment/pull-policy-demo (mutable-default)`
- `kv-e2e-image/Deployment/pull-policy-demo (safe-always)`
- `kv-e2e-image/Deployment/pull-policy-demo (latest-default)`

</details>

<details>
<summary>resource-requests-missing: 16 affected resources</summary>

- `kv-e2e-image/Deployment/disallowed-registry-demo (untrusted-app)`
- `kv-e2e-image/Deployment/disallowed-registry-demo (another-unknown)`
- `kv-e2e-image/Deployment/disallowed-registry-demo (trusted-pause)`
- `kv-e2e-image/Deployment/latest-tag-demo (explicit-latest)`
- `kv-e2e-image/Deployment/latest-tag-demo (implicit-latest)`
- `kv-e2e-image/Deployment/mixed-images-demo (app-mutable)`
- `kv-e2e-image/Deployment/mixed-images-demo (app-safe-tag)`
- `kv-e2e-image/Deployment/mixed-images-demo (init-no-tag)`
- `kv-e2e-image/Deployment/mixed-images-demo (sidecar-latest)`
- `kv-e2e-image/Deployment/mixed-images-demo (init-versioned)`
- `kv-e2e-image/Deployment/no-digest-demo (tag-only)`
- `kv-e2e-image/Deployment/no-digest-demo (tag-pinned)`
- `kv-e2e-image/Deployment/pull-policy-demo (mutable-ifnotpresent)`
- `kv-e2e-image/Deployment/pull-policy-demo (mutable-default)`
- `kv-e2e-image/Deployment/pull-policy-demo (safe-always)`
- `kv-e2e-image/Deployment/pull-policy-demo (latest-default)`

</details>

<details>
<summary>run-as-group: 16 affected resources</summary>

- `kv-e2e-image/Deployment/disallowed-registry-demo (untrusted-app)`
- `kv-e2e-image/Deployment/disallowed-registry-demo (another-unknown)`
- `kv-e2e-image/Deployment/disallowed-registry-demo (trusted-pause)`
- `kv-e2e-image/Deployment/latest-tag-demo (explicit-latest)`
- `kv-e2e-image/Deployment/latest-tag-demo (implicit-latest)`
- `kv-e2e-image/Deployment/mixed-images-demo (app-mutable)`
- `kv-e2e-image/Deployment/mixed-images-demo (app-safe-tag)`
- `kv-e2e-image/Deployment/mixed-images-demo (init-no-tag)`
- `kv-e2e-image/Deployment/mixed-images-demo (sidecar-latest)`
- `kv-e2e-image/Deployment/mixed-images-demo (init-versioned)`
- `kv-e2e-image/Deployment/no-digest-demo (tag-only)`
- `kv-e2e-image/Deployment/no-digest-demo (tag-pinned)`
- `kv-e2e-image/Deployment/pull-policy-demo (mutable-ifnotpresent)`
- `kv-e2e-image/Deployment/pull-policy-demo (mutable-default)`
- `kv-e2e-image/Deployment/pull-policy-demo (safe-always)`
- `kv-e2e-image/Deployment/pull-policy-demo (latest-default)`

</details>

<details>
<summary>seccomp-profile: 16 affected resources</summary>

- `kv-e2e-image/Deployment/disallowed-registry-demo (untrusted-app)`
- `kv-e2e-image/Deployment/disallowed-registry-demo (another-unknown)`
- `kv-e2e-image/Deployment/disallowed-registry-demo (trusted-pause)`
- `kv-e2e-image/Deployment/latest-tag-demo (explicit-latest)`
- `kv-e2e-image/Deployment/latest-tag-demo (implicit-latest)`
- `kv-e2e-image/Deployment/mixed-images-demo (app-mutable)`
- `kv-e2e-image/Deployment/mixed-images-demo (app-safe-tag)`
- `kv-e2e-image/Deployment/mixed-images-demo (init-no-tag)`
- `kv-e2e-image/Deployment/mixed-images-demo (sidecar-latest)`
- `kv-e2e-image/Deployment/mixed-images-demo (init-versioned)`
- `kv-e2e-image/Deployment/no-digest-demo (tag-only)`
- `kv-e2e-image/Deployment/no-digest-demo (tag-pinned)`
- `kv-e2e-image/Deployment/pull-policy-demo (mutable-ifnotpresent)`
- `kv-e2e-image/Deployment/pull-policy-demo (mutable-default)`
- `kv-e2e-image/Deployment/pull-policy-demo (safe-always)`
- `kv-e2e-image/Deployment/pull-policy-demo (latest-default)`

</details>

<details>
<summary>token-projection-config: 5 affected resources</summary>

- `kv-e2e-image/Deployment/disallowed-registry-demo`
- `kv-e2e-image/Deployment/latest-tag-demo`
- `kv-e2e-image/Deployment/mixed-images-demo`
- `kv-e2e-image/Deployment/no-digest-demo`
- `kv-e2e-image/Deployment/pull-policy-demo`

</details>

<details>
<summary>image-tag-latest: 5 affected resources</summary>

- `kv-e2e-image/Deployment/latest-tag-demo (explicit-latest)`
- `kv-e2e-image/Deployment/latest-tag-demo (implicit-latest)`
- `kv-e2e-image/Deployment/mixed-images-demo (init-no-tag)`
- `kv-e2e-image/Deployment/mixed-images-demo (sidecar-latest)`
- `kv-e2e-image/Deployment/pull-policy-demo (latest-default)`

</details>

<details>
<summary>image-tag-missing: 2 affected resources</summary>

- `kv-e2e-image/Deployment/latest-tag-demo (implicit-latest)`
- `kv-e2e-image/Deployment/mixed-images-demo (init-no-tag)`

</details>

<details>
<summary>ephemeral-storage-limits: 16 affected resources</summary>

- `kv-e2e-image/Deployment/disallowed-registry-demo (untrusted-app)`
- `kv-e2e-image/Deployment/disallowed-registry-demo (another-unknown)`
- `kv-e2e-image/Deployment/disallowed-registry-demo (trusted-pause)`
- `kv-e2e-image/Deployment/latest-tag-demo (explicit-latest)`
- `kv-e2e-image/Deployment/latest-tag-demo (implicit-latest)`
- `kv-e2e-image/Deployment/mixed-images-demo (app-mutable)`
- `kv-e2e-image/Deployment/mixed-images-demo (app-safe-tag)`
- `kv-e2e-image/Deployment/mixed-images-demo (init-no-tag)`
- `kv-e2e-image/Deployment/mixed-images-demo (sidecar-latest)`
- `kv-e2e-image/Deployment/mixed-images-demo (init-versioned)`
- `kv-e2e-image/Deployment/no-digest-demo (tag-only)`
- `kv-e2e-image/Deployment/no-digest-demo (tag-pinned)`
- `kv-e2e-image/Deployment/pull-policy-demo (mutable-ifnotpresent)`
- `kv-e2e-image/Deployment/pull-policy-demo (mutable-default)`
- `kv-e2e-image/Deployment/pull-policy-demo (safe-always)`
- `kv-e2e-image/Deployment/pull-policy-demo (latest-default)`

</details>

<details>
<summary>image-no-digest: 16 affected resources</summary>

- `kv-e2e-image/Deployment/disallowed-registry-demo (untrusted-app)`
- `kv-e2e-image/Deployment/disallowed-registry-demo (another-unknown)`
- `kv-e2e-image/Deployment/disallowed-registry-demo (trusted-pause)`
- `kv-e2e-image/Deployment/latest-tag-demo (explicit-latest)`
- `kv-e2e-image/Deployment/latest-tag-demo (implicit-latest)`
- `kv-e2e-image/Deployment/mixed-images-demo (app-mutable)`
- `kv-e2e-image/Deployment/mixed-images-demo (app-safe-tag)`
- `kv-e2e-image/Deployment/mixed-images-demo (init-no-tag)`
- `kv-e2e-image/Deployment/mixed-images-demo (sidecar-latest)`
- `kv-e2e-image/Deployment/mixed-images-demo (init-versioned)`
- `kv-e2e-image/Deployment/no-digest-demo (tag-only)`
- `kv-e2e-image/Deployment/no-digest-demo (tag-pinned)`
- `kv-e2e-image/Deployment/pull-policy-demo (mutable-ifnotpresent)`
- `kv-e2e-image/Deployment/pull-policy-demo (mutable-default)`
- `kv-e2e-image/Deployment/pull-policy-demo (safe-always)`
- `kv-e2e-image/Deployment/pull-policy-demo (latest-default)`

</details>

<details>
<summary>liveness-readiness-probes: 28 affected resources</summary>

- `kv-e2e-image/Deployment/disallowed-registry-demo (untrusted-app)`
- `kv-e2e-image/Deployment/disallowed-registry-demo (untrusted-app)`
- `kv-e2e-image/Deployment/disallowed-registry-demo (another-unknown)`
- `kv-e2e-image/Deployment/disallowed-registry-demo (another-unknown)`
- `kv-e2e-image/Deployment/disallowed-registry-demo (trusted-pause)`
- `kv-e2e-image/Deployment/disallowed-registry-demo (trusted-pause)`
- `kv-e2e-image/Deployment/latest-tag-demo (explicit-latest)`
- `kv-e2e-image/Deployment/latest-tag-demo (explicit-latest)`
- `kv-e2e-image/Deployment/latest-tag-demo (implicit-latest)`
- `kv-e2e-image/Deployment/latest-tag-demo (implicit-latest)`
- `kv-e2e-image/Deployment/mixed-images-demo (app-mutable)`
- `kv-e2e-image/Deployment/mixed-images-demo (app-mutable)`
- `kv-e2e-image/Deployment/mixed-images-demo (app-safe-tag)`
- `kv-e2e-image/Deployment/mixed-images-demo (app-safe-tag)`
- `kv-e2e-image/Deployment/mixed-images-demo (sidecar-latest)`
- `kv-e2e-image/Deployment/mixed-images-demo (sidecar-latest)`
- `kv-e2e-image/Deployment/no-digest-demo (tag-only)`
- `kv-e2e-image/Deployment/no-digest-demo (tag-only)`
- `kv-e2e-image/Deployment/no-digest-demo (tag-pinned)`
- `kv-e2e-image/Deployment/no-digest-demo (tag-pinned)`
- `kv-e2e-image/Deployment/pull-policy-demo (mutable-ifnotpresent)`
- `kv-e2e-image/Deployment/pull-policy-demo (mutable-ifnotpresent)`
- `kv-e2e-image/Deployment/pull-policy-demo (mutable-default)`
- `kv-e2e-image/Deployment/pull-policy-demo (mutable-default)`
- `kv-e2e-image/Deployment/pull-policy-demo (safe-always)`
- `kv-e2e-image/Deployment/pull-policy-demo (safe-always)`
- `kv-e2e-image/Deployment/pull-policy-demo (latest-default)`
- `kv-e2e-image/Deployment/pull-policy-demo (latest-default)`

</details>

<details>
<summary>priority-class-missing: 5 affected resources</summary>

- `kv-e2e-image/Deployment/disallowed-registry-demo`
- `kv-e2e-image/Deployment/latest-tag-demo`
- `kv-e2e-image/Deployment/mixed-images-demo`
- `kv-e2e-image/Deployment/no-digest-demo`
- `kv-e2e-image/Deployment/pull-policy-demo`

</details>

<details>
<summary>runtime-class: 5 affected resources</summary>

- `kv-e2e-image/Deployment/disallowed-registry-demo`
- `kv-e2e-image/Deployment/latest-tag-demo`
- `kv-e2e-image/Deployment/mixed-images-demo`
- `kv-e2e-image/Deployment/no-digest-demo`
- `kv-e2e-image/Deployment/pull-policy-demo`

</details>

<details>
<summary>topology-spread: 5 affected resources</summary>

- `kv-e2e-image/Deployment/disallowed-registry-demo`
- `kv-e2e-image/Deployment/latest-tag-demo`
- `kv-e2e-image/Deployment/mixed-images-demo`
- `kv-e2e-image/Deployment/no-digest-demo`
- `kv-e2e-image/Deployment/pull-policy-demo`

</details>

<details>
<summary>Remediation: automount-token (5 resources affected)</summary>

## Why This Matters

When a ServiceAccount token is auto-mounted, every container in the pod can call the Kubernetes API. If a container is compromised through a vulnerability or misconfiguration, the attacker gains API access to enumerate resources, read secrets, or escalate privileges.

## How to Fix

Disable auto-mounting at the pod spec level for workloads that do not need API access:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      automountServiceAccountToken: false
      containers:
        - name: app
          image: my-app:latest
```

For workloads that do require API access, use projected tokens with bounded lifetime and audience restrictions instead of the default long-lived token.

## Learn More

Refer to the Kubernetes documentation on configuring service accounts for pods and CIS Kubernetes Benchmark 5.1.6 for auto-mount token guidance.

**Affected resources:** kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/latest-tag-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/no-digest-demo, kv-e2e-image/Deployment/pull-policy-demo

</details>

<details>
<summary>Remediation: default-service-account (5 resources affected)</summary>

## Why This Matters

The default ServiceAccount is shared by every pod in a namespace. If any pod is compromised, the attacker inherits whatever permissions have been granted to the default account via role bindings, enabling lateral movement across all workloads sharing it.

## How to Fix

Create a dedicated ServiceAccount for each workload and reference it in the pod spec:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-app
  namespace: production
automountServiceAccountToken: false
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      serviceAccountName: my-app
```

Grant only the permissions the workload actually needs via a dedicated Role and RoleBinding.

## Learn More

See the Kubernetes documentation on managing service accounts and CIS Kubernetes Benchmark 5.1.5 for guidance on ensuring default service accounts are not actively used.

**Affected resources:** kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/latest-tag-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/no-digest-demo, kv-e2e-image/Deployment/pull-policy-demo

</details>

<details>
<summary>Remediation: privilege-escalation (16 resources affected)</summary>

## Why This Matters

By default, Kubernetes allows containers to escalate privileges via setuid/setgid binaries, which let a process gain more permissions than its parent. An attacker can exploit this using setuid binaries already present in the container image (like `su`, `sudo`, or `ping`) to elevate from a low-privilege user to root.

## How to Fix

Explicitly disable privilege escalation in the container's securityContext:

```yaml
securityContext:
  allowPrivilegeEscalation: false
  runAsNonRoot: true
  capabilities:
    drop: ["ALL"]
```

This blocks the use of setuid/setgid binaries and prevents the no_new_privs Linux flag from being cleared. The vast majority of application containers do not need privilege escalation.

## Learn More

This is required by the Pod Security Standards "Restricted" profile and CIS Benchmark 5.2.5. Disabling privilege escalation is one of the most impactful single-line security improvements you can make.

**Affected resources:** kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/latest-tag-demo, kv-e2e-image/Deployment/latest-tag-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/no-digest-demo, kv-e2e-image/Deployment/no-digest-demo, kv-e2e-image/Deployment/pull-policy-demo, kv-e2e-image/Deployment/pull-policy-demo, kv-e2e-image/Deployment/pull-policy-demo, kv-e2e-image/Deployment/pull-policy-demo

</details>

<details>
<summary>Remediation: run-as-root (16 resources affected)</summary>

## Why This Matters

Without `runAsNonRoot: true`, Kubernetes does not enforce non-root execution and the container may default to running as UID 0 depending on the image's USER directive. If the image defaults to root, the container process gains full privileges, increasing the blast radius of any compromise or container escape.

## How to Fix

Enforce non-root execution in the securityContext:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
```

With `runAsNonRoot: true`, Kubernetes will reject the pod at admission time if the container image attempts to run as root. Setting an explicit `runAsUser` provides an additional guarantee.

## Learn More

This aligns with CIS Benchmark 5.2.6 and the Pod Security Standards "Restricted" profile. The `runAsNonRoot` field acts as a safety net even when images change their default USER.

**Affected resources:** kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/latest-tag-demo, kv-e2e-image/Deployment/latest-tag-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/no-digest-demo, kv-e2e-image/Deployment/no-digest-demo, kv-e2e-image/Deployment/pull-policy-demo, kv-e2e-image/Deployment/pull-policy-demo, kv-e2e-image/Deployment/pull-policy-demo, kv-e2e-image/Deployment/pull-policy-demo

</details>

<details>
<summary>Remediation: network-policy-missing (1 resources affected)</summary>

## Why This Matters

Without NetworkPolicies, every pod in this namespace can communicate freely with every other pod in the cluster. If an attacker compromises a single pod, they can move laterally to databases, internal APIs, and other sensitive services with no network-level barriers.

## How to Fix

Create a default-deny NetworkPolicy for the namespace, then add targeted allow rules for legitimate traffic:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: my-namespace
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
```

After applying the default-deny, create additional NetworkPolicy resources that whitelist only the specific ingress and egress flows your workloads require.

## Learn More

See the Kubernetes documentation on NetworkPolicies and CIS Kubernetes Benchmark 5.3.2. A CNI plugin that supports NetworkPolicy (Calico, Cilium, Weave Net) must be installed for policies to take effect.

**Affected resources:** kv-e2e-image/Namespace/kv-e2e-image

</details>

<details>
<summary>Remediation: apparmor-profile (16 resources affected)</summary>

## Why This Matters

AppArmor provides mandatory access control (MAC) that restricts which files, network resources, and capabilities a container process can access. Without an AppArmor profile, the container operates without these restrictions, allowing an attacker with code execution to access any file the container user can read and make unrestricted network connections.

## How to Fix

Apply an AppArmor profile in the container's securityContext (Kubernetes 1.30+):

```yaml
securityContext:
  appArmorProfile:
    type: RuntimeDefault
```

The RuntimeDefault profile provides sensible restrictions for most applications. For tighter control, create a custom Localhost profile that only allows the specific file and network access your application needs.

## Learn More

AppArmor is available on Debian/Ubuntu-based nodes. RHEL/CentOS nodes use SELinux instead. Both provide MAC enforcement. Refer to CIS Benchmark 5.7.5 and the Kubernetes AppArmor documentation.

**Affected resources:** kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/latest-tag-demo, kv-e2e-image/Deployment/latest-tag-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/no-digest-demo, kv-e2e-image/Deployment/no-digest-demo, kv-e2e-image/Deployment/pull-policy-demo, kv-e2e-image/Deployment/pull-policy-demo, kv-e2e-image/Deployment/pull-policy-demo, kv-e2e-image/Deployment/pull-policy-demo

</details>

<details>
<summary>Remediation: capabilities-not-dropped (16 resources affected)</summary>

## Why This Matters

By default, containers receive a set of Linux capabilities including KILL, SETUID, SETGID, and NET_RAW. These defaults are rarely needed by application code and significantly increase the potential damage from a container compromise. Dropping all capabilities follows the principle of least privilege.

## How to Fix

Explicitly drop all capabilities and selectively add back only what your application needs:

```yaml
securityContext:
  capabilities:
    drop: ["ALL"]
    add: ["NET_BIND_SERVICE"]  # Only if needed
```

Most web applications, API servers, and background workers run perfectly with all capabilities dropped. Test your application after making this change to confirm no functionality is lost.

## Learn More

This is required by the Pod Security Standards "Restricted" profile and aligns with CIS Benchmark 5.2.7. Kubernetes best practice is to treat capability grants as exceptions that require explicit justification.

**Affected resources:** kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/latest-tag-demo, kv-e2e-image/Deployment/latest-tag-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/no-digest-demo, kv-e2e-image/Deployment/no-digest-demo, kv-e2e-image/Deployment/pull-policy-demo, kv-e2e-image/Deployment/pull-policy-demo, kv-e2e-image/Deployment/pull-policy-demo, kv-e2e-image/Deployment/pull-policy-demo

</details>

<details>
<summary>Remediation: image-pull-policy (6 resources affected)</summary>

## Why This Matters

When a mutable image tag is used without `imagePullPolicy: Always`, Kubernetes may serve a cached version of the image from the node. If the tag has been updated in the registry (with a security patch or -- worse -- a compromised layer), the running container will not reflect those changes.

## How to Fix

Set `imagePullPolicy: Always` for any container using a mutable tag:

```yaml
containers:
  - name: app
    image: nginx:1.25.3
    imagePullPolicy: Always   # Forces fresh pull each time
```

Alternatively, pin images by digest (`image@sha256:...`), which makes the pull policy irrelevant because the content is immutable.

## Learn More

See the Kubernetes documentation on image pull policies and CIS Kubernetes Benchmark 5.4.2 for pull policy guidance.

**Affected resources:** kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/pull-policy-demo, kv-e2e-image/Deployment/pull-policy-demo

</details>

<details>
<summary>Remediation: psa-restricted-violations (48 resources affected)</summary>

## Why This Matters

Running as root inside a container means that any container escape vulnerability immediately grants root access on the host node. Even without an escape, root inside the container can modify sensitive files, install packages, and access capabilities that non-root users cannot.

## How to Fix

Set `runAsNonRoot: true` and specify a non-root user ID in the security context:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
```

Set this at the pod level to apply to all containers. Ensure your container image supports running as a non-root user (many official images do).

## Learn More

See the Pod Security Standards Restricted profile and CIS Kubernetes Benchmark 5.2.6. Running as non-root is a fundamental container security best practice.

**Affected resources:** kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/latest-tag-demo, kv-e2e-image/Deployment/latest-tag-demo, kv-e2e-image/Deployment/latest-tag-demo, kv-e2e-image/Deployment/latest-tag-demo, kv-e2e-image/Deployment/latest-tag-demo, kv-e2e-image/Deployment/latest-tag-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/no-digest-demo, kv-e2e-image/Deployment/no-digest-demo, kv-e2e-image/Deployment/no-digest-demo, kv-e2e-image/Deployment/no-digest-demo, kv-e2e-image/Deployment/no-digest-demo, kv-e2e-image/Deployment/no-digest-demo, kv-e2e-image/Deployment/pull-policy-demo, kv-e2e-image/Deployment/pull-policy-demo, kv-e2e-image/Deployment/pull-policy-demo, kv-e2e-image/Deployment/pull-policy-demo, kv-e2e-image/Deployment/pull-policy-demo, kv-e2e-image/Deployment/pull-policy-demo, kv-e2e-image/Deployment/pull-policy-demo, kv-e2e-image/Deployment/pull-policy-demo, kv-e2e-image/Deployment/pull-policy-demo, kv-e2e-image/Deployment/pull-policy-demo, kv-e2e-image/Deployment/pull-policy-demo, kv-e2e-image/Deployment/pull-policy-demo

</details>

<details>
<summary>Remediation: read-only-rootfs (16 resources affected)</summary>

## Why This Matters

A writable root filesystem allows an attacker who gains code execution in your container to modify application binaries, install attack tools, plant backdoors, or persist malware across container restarts. Making the filesystem read-only eliminates an entire class of post-exploitation techniques.

## How to Fix

Enable a read-only root filesystem and mount writable volumes only where needed:

```yaml
securityContext:
  readOnlyRootFilesystem: true
volumeMounts:
  - name: tmp
    mountPath: /tmp
volumes:
  - name: tmp
    emptyDir: {}
```

Common paths that need write access include /tmp, /var/cache, and /var/run. Mount each as an emptyDir or tmpfs volume rather than making the entire filesystem writable.

## Learn More

This aligns with CIS Benchmark 5.2.4 and the defense-in-depth principle. Combined with dropping capabilities and running as non-root, a read-only filesystem forms a strong container hardening baseline.

**Affected resources:** kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/latest-tag-demo, kv-e2e-image/Deployment/latest-tag-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/no-digest-demo, kv-e2e-image/Deployment/no-digest-demo, kv-e2e-image/Deployment/pull-policy-demo, kv-e2e-image/Deployment/pull-policy-demo, kv-e2e-image/Deployment/pull-policy-demo, kv-e2e-image/Deployment/pull-policy-demo

</details>

<details>
<summary>Remediation: resource-requests-missing (16 resources affected)</summary>

## Why This Matters

Resource requests tell the Kubernetes scheduler how much CPU and memory your container needs. Without requests, the scheduler treats the pod as needing zero resources and may pack too many pods onto a single node. This leads to overcommitment, resource contention, throttling, and OOM kills under load.

## How to Fix

Set resource requests based on your application's steady-state usage:

```yaml
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 256Mi
```

Observe your application's actual resource consumption using `kubectl top` or a monitoring tool, then set requests to match the typical steady-state usage.

## Learn More

Resource requests determine the pod's QoS class and scheduling behavior. Pods with requests equal to limits receive Guaranteed QoS. Use Vertical Pod Autoscaler (VPA) to automatically recommend request values.

**Affected resources:** kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/latest-tag-demo, kv-e2e-image/Deployment/latest-tag-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/no-digest-demo, kv-e2e-image/Deployment/no-digest-demo, kv-e2e-image/Deployment/pull-policy-demo, kv-e2e-image/Deployment/pull-policy-demo, kv-e2e-image/Deployment/pull-policy-demo, kv-e2e-image/Deployment/pull-policy-demo

</details>

<details>
<summary>Remediation: run-as-group (16 resources affected)</summary>

## Why This Matters

Without an explicit runAsGroup, the container process defaults to GID 0 (the root group). Files and sockets owned by the root group become accessible to the container, including potentially sensitive host files if volumes are mounted. This widens the attack surface unnecessarily.

## How to Fix

Set an explicit non-root group in the securityContext:

```yaml
securityContext:
  runAsGroup: 1000
  runAsUser: 1000
  runAsNonRoot: true
```

Ensure the container image's application files and directories are readable by the specified GID. You may need to adjust file ownership in your Dockerfile with `chown`.

## Learn More

This aligns with CIS Benchmark 5.2.6 and the Pod Security Standards "Restricted" profile. Always set runAsUser, runAsGroup, and runAsNonRoot together for comprehensive identity control.

**Affected resources:** kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/latest-tag-demo, kv-e2e-image/Deployment/latest-tag-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/no-digest-demo, kv-e2e-image/Deployment/no-digest-demo, kv-e2e-image/Deployment/pull-policy-demo, kv-e2e-image/Deployment/pull-policy-demo, kv-e2e-image/Deployment/pull-policy-demo, kv-e2e-image/Deployment/pull-policy-demo

</details>

<details>
<summary>Remediation: seccomp-profile (16 resources affected)</summary>

## Why This Matters

Without a Seccomp profile, containers can invoke any of the 300+ Linux system calls, leaving the entire kernel attack surface exposed. Kernel vulnerabilities in obscure syscalls are a primary vector for container escapes. Seccomp filtering blocks dangerous syscalls that legitimate applications never use.

## How to Fix

Apply a Seccomp profile at the container or pod level:

```yaml
securityContext:
  seccompProfile:
    type: RuntimeDefault
```

The RuntimeDefault profile blocks approximately 50 dangerous syscalls while allowing normal application behavior. For stricter controls, use a custom Localhost profile tailored to your application's needs. Set the profile at the pod level to apply it to all containers.

## Learn More

Seccomp profiles are required by the Pod Security Standards "Restricted" profile and CIS Benchmark 5.7.2. Use tools like `strace` or the Security Profiles Operator to generate custom profiles for your workloads.

**Affected resources:** kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/latest-tag-demo, kv-e2e-image/Deployment/latest-tag-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/no-digest-demo, kv-e2e-image/Deployment/no-digest-demo, kv-e2e-image/Deployment/pull-policy-demo, kv-e2e-image/Deployment/pull-policy-demo, kv-e2e-image/Deployment/pull-policy-demo, kv-e2e-image/Deployment/pull-policy-demo

</details>

<details>
<summary>Remediation: token-projection-config (5 resources affected)</summary>

## Why This Matters

Without explicit projection configuration, ServiceAccount tokens use Kubernetes defaults: no audience restriction and a long expiration. A stolen token remains valid for an extended period and can be used against any API server endpoint, widening the blast radius of a compromise.

## How to Fix

Add a projected volume with explicit expiration and audience:

```yaml
spec:
  volumes:
    - name: token
      projected:
        sources:
          - serviceAccountToken:
              expirationSeconds: 3600
              audience: my-api
              path: token
  containers:
    - name: app
      volumeMounts:
        - name: token
          mountPath: /var/run/secrets/tokens
          readOnly: true
```

Projected tokens auto-rotate before expiry and are rejected by endpoints outside the specified audience.

## Learn More

See the Kubernetes documentation on projected volumes and service account token volume projection for detailed configuration options.

**Affected resources:** kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/latest-tag-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/no-digest-demo, kv-e2e-image/Deployment/pull-policy-demo

</details>

<details>
<summary>Remediation: network-policy-egress-unrestricted (1 resources affected)</summary>

## Why This Matters

Without any egress NetworkPolicy in this namespace, pods can freely send traffic to any destination including the public internet. A compromised pod can exfiltrate sensitive data, reach cloud metadata services (e.g., 169.254.169.254), or establish reverse shells to attacker-controlled servers.

## How to Fix

Create a NetworkPolicy with `Egress` in `policyTypes` to restrict outbound traffic. At minimum, allow DNS resolution:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-egress
  namespace: my-namespace
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector: {}
      ports:
        - port: 53
          protocol: UDP
```

Add additional egress rules for specific services your workloads need to reach.

## Learn More

See the Kubernetes NetworkPolicy documentation and CIS Kubernetes Benchmark 5.3.2. Egress controls are a key defense-in-depth measure recommended by the NSA/CISA Kubernetes Hardening Guide.

**Affected resources:** kv-e2e-image/Namespace/kv-e2e-image

</details>

<details>
<summary>Remediation: psa-labels-missing (1 resources affected)</summary>

## Why This Matters

Without PSA enforcement labels, any pod configuration is allowed in this namespace, including privileged containers, host namespace access, and root execution. This bypasses Kubernetes' built-in Pod Security Standards and leaves the namespace vulnerable to workloads that could compromise the node.

## How to Fix

Add Pod Security Admission labels to enforce a security profile on all pods in the namespace:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: kv-e2e-image
  labels:
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

Start with `baseline` enforcement to block known privilege escalations, then upgrade to `restricted` after verifying all workloads are compliant.

## Learn More

See the Kubernetes Pod Security Admission documentation and CIS Kubernetes Benchmark 5.2. The three-tier approach (enforce, audit, warn) allows gradual adoption of stricter profiles.

**Affected resources:** kv-e2e-image/Namespace/kv-e2e-image

</details>

<details>
<summary>Remediation: image-tag-latest (5 resources affected)</summary>

## Why This Matters

The :latest tag is mutable and can resolve to a different image at any time. Deployments become non-reproducible, rollbacks break silently, and attackers can poison the tag to inject malicious code without changing your manifests.

## How to Fix

Pin every container image to a specific, immutable version tag:

```yaml
containers:
  - name: app
    image: nginx:1.25.3          # Pinned version tag
    # Or pin by digest for maximum immutability:
    # image: nginx@sha256:a8281ce42034
```

Adopt a CI/CD practice of updating image tags via automated PRs so manifests always reflect the exact version deployed.

## Learn More

The CIS Kubernetes Benchmark 5.4.1 recommends pinning image versions. See the Kubernetes documentation on container images for tag best practices.

**Affected resources:** kv-e2e-image/Deployment/latest-tag-demo, kv-e2e-image/Deployment/latest-tag-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/pull-policy-demo

</details>

<details>
<summary>Remediation: image-tag-missing (2 resources affected)</summary>

## Why This Matters

An image reference with no tag and no digest implicitly resolves to :latest, which is mutable. Every pod restart could pull a completely different image, breaking reproducibility and opening the door to supply chain attacks.

## How to Fix

Always specify an explicit version tag or content-addressable digest:

```yaml
containers:
  - name: app
    image: nginx:1.25.3              # Explicit version tag
    # Or for critical workloads, pin by digest:
    # image: nginx@sha256:a8281ce42034
```

Integrate image tag linting into your CI pipeline to catch missing tags before manifests reach the cluster.

## Learn More

Kubernetes documentation recommends always specifying an image tag. See CIS Kubernetes Benchmark 5.4.1 for image versioning requirements.

**Affected resources:** kv-e2e-image/Deployment/latest-tag-demo, kv-e2e-image/Deployment/mixed-images-demo

</details>

<details>
<summary>Remediation: ephemeral-storage-limits (16 resources affected)</summary>

## Why This Matters

Ephemeral storage includes container logs, emptyDir volumes, and the writable container layer. Without limits, a single container can fill the node's root disk, triggering eviction of all pods on that node and potentially causing a cascading failure across your cluster. This is a common denial-of-service vector.

## How to Fix

Set ephemeral-storage limits alongside your CPU and memory limits:

```yaml
resources:
  limits:
    ephemeral-storage: 1Gi
  requests:
    ephemeral-storage: 500Mi
```

Estimate your application's disk usage from logs, temporary files, and cache data. If your application writes large temporary files, consider using a PersistentVolumeClaim instead of ephemeral storage.

## Learn More

The kubelet evicts pods that exceed their ephemeral-storage limit. Use LimitRange to set default ephemeral-storage limits at the namespace level to catch containers that omit this setting.

**Affected resources:** kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/latest-tag-demo, kv-e2e-image/Deployment/latest-tag-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/no-digest-demo, kv-e2e-image/Deployment/no-digest-demo, kv-e2e-image/Deployment/pull-policy-demo, kv-e2e-image/Deployment/pull-policy-demo, kv-e2e-image/Deployment/pull-policy-demo, kv-e2e-image/Deployment/pull-policy-demo

</details>

<details>
<summary>Remediation: image-no-digest (16 resources affected)</summary>

## Why This Matters

Image tags are mutable pointers -- a registry administrator or attacker can re-push a different image under the same tag. Without a digest, you have no cryptographic guarantee that the image you deploy is the one you tested.

## How to Fix

Pin images by their SHA-256 content digest for a fully immutable reference:

```yaml
containers:
  - name: app
    image: nginx@sha256:a8281ce420348a01ea6e   # Immutable
```

Use `crane digest nginx:1.25.3` or `skopeo inspect` to resolve a tag to its digest during CI/CD, then commit the pinned reference.

## Learn More

SLSA Level 1+ and NIST SP 800-190 recommend digest pinning for container supply chain integrity. See the Kubernetes images documentation for details.

**Affected resources:** kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/latest-tag-demo, kv-e2e-image/Deployment/latest-tag-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/no-digest-demo, kv-e2e-image/Deployment/no-digest-demo, kv-e2e-image/Deployment/pull-policy-demo, kv-e2e-image/Deployment/pull-policy-demo, kv-e2e-image/Deployment/pull-policy-demo, kv-e2e-image/Deployment/pull-policy-demo

</details>

<details>
<summary>Remediation: liveness-readiness-probes (28 resources affected)</summary>

## Why This Matters

Without a liveness probe, Kubernetes cannot detect when a container has become unresponsive or deadlocked. The container continues running and consuming resources while failing to serve traffic. Users experience timeouts and errors until someone manually intervenes.

## How to Fix

Add a liveness probe that checks the container's health:

```yaml
containers:
  - name: app
    livenessProbe:
      httpGet:
        path: /healthz
        port: 8080
      initialDelaySeconds: 15
      periodSeconds: 10
      failureThreshold: 3
```

Use `httpGet` for HTTP services, `tcpSocket` for TCP services, or `exec` with a custom health check script for non-network workloads.

## Learn More

See the Kubernetes documentation on container probes. Set initialDelaySeconds high enough for your application to start, and consider adding a startupProbe for slow-starting containers.

**Affected resources:** kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/latest-tag-demo, kv-e2e-image/Deployment/latest-tag-demo, kv-e2e-image/Deployment/latest-tag-demo, kv-e2e-image/Deployment/latest-tag-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/no-digest-demo, kv-e2e-image/Deployment/no-digest-demo, kv-e2e-image/Deployment/no-digest-demo, kv-e2e-image/Deployment/no-digest-demo, kv-e2e-image/Deployment/pull-policy-demo, kv-e2e-image/Deployment/pull-policy-demo, kv-e2e-image/Deployment/pull-policy-demo, kv-e2e-image/Deployment/pull-policy-demo, kv-e2e-image/Deployment/pull-policy-demo, kv-e2e-image/Deployment/pull-policy-demo, kv-e2e-image/Deployment/pull-policy-demo, kv-e2e-image/Deployment/pull-policy-demo

</details>

<details>
<summary>Remediation: priority-class-missing (5 resources affected)</summary>

## Why This Matters

Without a PriorityClass, pods receive default priority (typically 0) and are among the first to be evicted during resource pressure or node maintenance. This means important application workloads may be killed before less critical ones, leading to unpredictable outages.

## How to Fix

Define PriorityClasses for your workloads and assign them appropriately:

```yaml
apiVersion: scheduling.k8s.io/v1
kind: PriorityClass
metadata:
  name: app-medium
value: 100000
---
# Reference in your workload:
spec:
  priorityClassName: app-medium
```

Create a tiered priority scheme (e.g., app-critical: 500000, app-medium: 100000, app-low: 10000) that reflects your workload importance hierarchy.

## Learn More

Refer to the Kubernetes Pod Priority and Preemption documentation. Establishing a consistent priority scheme across namespaces ensures predictable eviction behavior during resource contention.

**Affected resources:** kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/latest-tag-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/no-digest-demo, kv-e2e-image/Deployment/pull-policy-demo

</details>

<details>
<summary>Remediation: runtime-class (5 resources affected)</summary>

## Why This Matters

Without a RuntimeClass, pods use the default container runtime (typically runc), which shares the host kernel directly with containers. A kernel vulnerability can allow container escape to the host. Sandboxed runtimes like gVisor or Kata Containers add an additional isolation layer that intercepts system calls or runs containers in lightweight VMs.

## How to Fix

Specify a sandboxed RuntimeClass in the pod spec:

```yaml
spec:
  runtimeClassName: gvisor
```

Available RuntimeClasses depend on your cluster configuration. Common options include `gvisor` (user-space kernel), `kata` (micro-VMs), and `firecracker`. Check your cluster's available RuntimeClasses with `kubectl get runtimeclasses`.

## Learn More

Sandboxed runtimes are especially important for multi-tenant clusters and workloads processing untrusted input. They add latency overhead, so evaluate performance requirements. See the Kubernetes RuntimeClass documentation.

**Affected resources:** kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/latest-tag-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/no-digest-demo, kv-e2e-image/Deployment/pull-policy-demo

</details>

<details>
<summary>Remediation: topology-spread (5 resources affected)</summary>

## Why This Matters

Without topology spread constraints, the scheduler may place all replicas on the same node or in the same availability zone. If that node or zone fails, your entire service goes down despite having multiple replicas. This negates the high-availability benefits of running multiple pods.

## How to Fix

Add topology spread constraints to distribute replicas across failure domains:

```yaml
spec:
  topologySpreadConstraints:
    - maxSkew: 1
      topologyKey: kubernetes.io/hostname
      whenUnsatisfiable: DoNotSchedule
      labelSelector:
        matchLabels:
          app: my-app
    - maxSkew: 1
      topologyKey: topology.kubernetes.io/zone
      whenUnsatisfiable: ScheduleAnyway
```

Use `kubernetes.io/hostname` for node-level spreading and `topology.kubernetes.io/zone` for zone-level spreading.

## Learn More

See the Kubernetes Pod Topology Spread Constraints documentation. Combining hostname and zone constraints provides both node-level and zone-level fault tolerance.

**Affected resources:** kv-e2e-image/Deployment/disallowed-registry-demo, kv-e2e-image/Deployment/latest-tag-demo, kv-e2e-image/Deployment/mixed-images-demo, kv-e2e-image/Deployment/no-digest-demo, kv-e2e-image/Deployment/pull-policy-demo

</details>

<details>
<summary>Remediation: limit-range-missing (1 resources affected)</summary>

## Why This Matters

Without a LimitRange, any container can be created without resource constraints. A single runaway or malicious pod can consume all node CPU and memory, causing denial of service for other workloads on the same node.

## How to Fix

Create a LimitRange in the namespace to set default and maximum resource constraints:

```yaml
apiVersion: v1
kind: LimitRange
metadata:
  name: default-limits
  namespace: my-app
spec:
  limits:
    - type: Container
      default:
        cpu: 500m
        memory: 256Mi
      defaultRequest:
        cpu: 100m
        memory: 128Mi
      max:
        cpu: "2"
        memory: 1Gi
```

Containers that omit resource requests/limits will inherit these defaults automatically.

## Learn More

CIS Kubernetes Benchmark 5.2.1 recommends LimitRanges for resource governance. See https://kubernetes.io/docs/concepts/policy/limit-range/ for configuration details.

**Affected resources:** kv-e2e-image/Namespace/kv-e2e-image

</details>

<details>
<summary>Remediation: resource-quota-missing (1 resources affected)</summary>

## Why This Matters

Without a ResourceQuota, a single namespace can consume the entire cluster's CPU, memory, and storage. This creates a noisy-neighbor problem where one team's workloads starve others, and makes capacity planning impossible.

## How to Fix

Create a ResourceQuota to cap the namespace's total resource consumption:

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: compute-quota
  namespace: my-app
spec:
  hard:
    requests.cpu: "10"
    requests.memory: 20Gi
    limits.cpu: "20"
    limits.memory: 40Gi
    pods: "50"
    services: "10"
```

Tune quota values based on the namespace's actual workload requirements and cluster capacity.

## Learn More

CIS Kubernetes Benchmark 5.2.2 recommends ResourceQuotas for multi-tenant clusters. See https://kubernetes.io/docs/concepts/policy/resource-quotas/ for quota configuration and enforcement behavior.

**Affected resources:** kv-e2e-image/Namespace/kv-e2e-image

</details>

### kv-e2e-mixed (143 findings — 🟠26 🟡68 🔵49)

| Severity | Check | Resources | Message | Frameworks |
|----------|-------|-----------|---------|-----------|
| 🟠 High | automount-token | **6 resources** | Deployment "backend" auto-mounts a ServiceAccount token. Most workloads do not need Kubernetes API access. | CIS 5.1.6 · MITRE T1552.007 · NSA 3.2 |
| 🟠 High | capabilities-added | kv-e2e-mixed/Deployment/backend (api) | Container "api" adds dangerous capabilities: NET_BIND_SERVICE. | CIS 5.2.9 · CIS 5.2.10 · MITRE T1611 · MITRE T1068 · NSA 1.1 · NSA 2.1 |
| 🟠 High | default-service-account | **5 resources** | Deployment "backend" uses the default ServiceAccount, which may have unintended permissions. | CIS 5.1.5 · CIS 5.1.6 · MITRE T1078.001 · NSA 3.1 · NSA 3.2 |
| 🟠 High | privilege-escalation | **6 resources** | Container "api" does not set allowPrivilegeEscalation to false, permitting privilege escalation. | CIS 5.2.6 · MITRE T1068 · MITRE T1611 · NSA 1.1 · NSA 2.1 |
| 🟠 High | run-as-root | **5 resources** | Container "api" does not set runAsNonRoot: true and may run as root. | CIS 5.2.7 · MITRE T1611 · NSA 1.1 |
| 🟠 High | host-ports | kv-e2e-mixed/Deployment/cache (redis) | Container "redis" binds to host port 6379, exposing the service directly on the node. | CIS 5.2.13 · MITRE T1611 · NSA 1.3 |
| 🟠 High | network-policy-default-deny | **2 resources** | Namespace "kv-e2e-mixed" is missing a default-deny ingress NetworkPolicy. | CIS 5.3.2 · MITRE T1046 · MITRE T1071 · NSA 4.2 |
| 🟡 Medium | apparmor-profile | **6 resources** | Container "api" does not have an AppArmor profile set. | CIS 5.6.3 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | capabilities-not-dropped | **6 resources** | Container "api" does not drop ALL capabilities, leaving it with unnecessary default privileges. | CIS 5.2.8 · CIS 5.2.10 · MITRE T1068 · NSA 1.1 |
| 🟡 Medium | image-pull-policy | **3 resources** | Container "api" uses a mutable image tag with pullPolicy "IfNotPresent" (image: busybox:1.36), risking stale images. | CIS 5.5.1 · MITRE T1525 · NSA 1.4 |
| 🟡 Medium | psa-restricted-violations | **17 resources** | Deployment "backend" container "api" violates PSS Restricted: runAsNonRoot is not true. | CIS 5.2.1 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | read-only-rootfs | **5 resources** | Container "api" does not have a read-only root filesystem. | CIS 5.6.3 · MITRE T1565.001 · NSA 1.2 |
| 🟡 Medium | run-as-group | **6 resources** | Container "api" does not set runAsGroup; the process will run as GID 0 (root group) by default. | CIS 5.2.7 · MITRE T1068 · NSA 1.1 |
| 🟡 Medium | seccomp-profile | **6 resources** | Container "api" does not have a Seccomp profile set at either the container or pod level. | CIS 5.6.2 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | secrets-in-env | kv-e2e-mixed/Deployment/backend (api) | container "api" passes secret "db-credentials" key "password" via environment variable | CIS 5.4.1 · CIS 5.4.2 · MITRE T1552 · NSA 5.1 |
| 🟡 Medium | token-projection-config | **6 resources** | Deployment "backend" does not use explicitly configured projected ServiceAccount tokens with expiry and audience restrictions. | CIS 5.1.6 · MITRE T1552.007 · NSA 3.2 |
| 🟡 Medium | resource-limits-missing | **2 resources** | Container "redis" is missing both CPU and memory limits. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🟡 Medium | resource-requests-missing | **3 resources** | Container "redis" is missing both CPU and memory requests. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🟡 Medium | host-path-volumes | kv-e2e-mixed/Deployment/database | Deployment "database" mounts hostPath "/mnt/data/postgres" via volume "data". | CIS 5.2.12 · MITRE T1611 · MITRE T1006 · NSA 1.3 |
| 🟡 Medium | image-tag-latest | **3 resources** | Container "nginx" uses the :latest tag (image: nginx:latest), which can lead to unpredictable deployments. | CIS 5.5.1 · MITRE T1525 · NSA 1.4 |
| 🟡 Medium | network-policy-egress-unrestricted | kv-e2e-mixed/Namespace/kv-e2e-mixed | Namespace "kv-e2e-mixed" has no NetworkPolicy with egress restrictions. Pods can reach any external destination. | CIS 5.3.2 · MITRE T1048 · NSA 4.2 |
| 🟡 Medium | psa-labels-missing | kv-e2e-mixed/Namespace/kv-e2e-mixed | Namespace "kv-e2e-mixed" is missing the pod-security.kubernetes.io/enforce label; pod security is not enforced. | CIS 5.2.1 · MITRE T1610 · NSA 2.1 |
| 🟡 Medium | network-policy-overly-permissive | kv-e2e-mixed/NetworkPolicy/partially-hardened-policy | NetworkPolicy "partially-hardened-policy" allows all ingress traffic, providing no effective ingress segmentation. | CIS 5.3.2 · MITRE T1046 · NSA 4.2 |
| 🔵 Low | ephemeral-storage-limits | **6 resources** | Container "api" is missing ephemeral-storage limits. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | image-no-digest | **6 resources** | Container "api" image is not pinned by digest (image: busybox:1.36), allowing tag mutation. | CIS 5.5.1 · MITRE T1525 · NSA 1.4 |
| 🔵 Low | liveness-readiness-probes | **12 resources** | Container "api" has no liveness probe configured. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | pod-disruption-budget | **3 resources** | Deployment "backend" has 2 replicas but no matching PodDisruptionBudget; all replicas can be evicted simultaneously. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | priority-class-missing | **6 resources** | Deployment "backend" has no PriorityClass set; it will be evicted first during resource pressure. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | runtime-class | **6 resources** | Pod "backend" does not specify a RuntimeClass, using the default (unsandboxed) runtime. | CIS 5.6.3 · MITRE T1611 · NSA 2.1 |
| 🔵 Low | topology-spread | **6 resources** | Deployment "backend" has no topology spread constraints; all replicas may be scheduled on the same node. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | run-as-high-uid | kv-e2e-mixed/Deployment/database (postgres) | Container "postgres" runs as UID 999, which is below the recommended minimum of 10000. | CIS 5.2.7 · MITRE T1068 · NSA 1.1 |
| 🔵 Low | limit-range-missing | kv-e2e-mixed/Namespace/kv-e2e-mixed | Namespace "kv-e2e-mixed" has no LimitRange defined. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | resource-quota-missing | kv-e2e-mixed/Namespace/kv-e2e-mixed | Namespace "kv-e2e-mixed" has no ResourceQuota defined. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | emptydir-size-limit | kv-e2e-mixed/Deployment/partially-hardened-app | Deployment "partially-hardened-app" has emptyDir volume "tmp" without sizeLimit; a container can fill the node disk. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |

<details>
<summary>automount-token: 6 affected resources</summary>

- `kv-e2e-mixed/Deployment/backend`
- `kv-e2e-mixed/Deployment/cache`
- `kv-e2e-mixed/Deployment/database`
- `kv-e2e-mixed/Deployment/frontend`
- `kv-e2e-mixed/Deployment/partially-hardened-app`
- `kv-e2e-mixed/Deployment/startup-web-app`

</details>

<details>
<summary>default-service-account: 5 affected resources</summary>

- `kv-e2e-mixed/Deployment/backend`
- `kv-e2e-mixed/Deployment/cache`
- `kv-e2e-mixed/Deployment/database`
- `kv-e2e-mixed/Deployment/frontend`
- `kv-e2e-mixed/Deployment/startup-web-app`

</details>

<details>
<summary>privilege-escalation: 6 affected resources</summary>

- `kv-e2e-mixed/Deployment/backend (api)`
- `kv-e2e-mixed/Deployment/cache (redis)`
- `kv-e2e-mixed/Deployment/database (postgres)`
- `kv-e2e-mixed/Deployment/frontend (nginx)`
- `kv-e2e-mixed/Deployment/partially-hardened-app (app)`
- `kv-e2e-mixed/Deployment/startup-web-app (web)`

</details>

<details>
<summary>run-as-root: 5 affected resources</summary>

- `kv-e2e-mixed/Deployment/backend (api)`
- `kv-e2e-mixed/Deployment/cache (redis)`
- `kv-e2e-mixed/Deployment/frontend (nginx)`
- `kv-e2e-mixed/Deployment/partially-hardened-app (app)`
- `kv-e2e-mixed/Deployment/startup-web-app (web)`

</details>

<details>
<summary>network-policy-default-deny: 2 affected resources</summary>

- `kv-e2e-mixed/Namespace/kv-e2e-mixed`
- `kv-e2e-mixed/Namespace/kv-e2e-mixed`

</details>

<details>
<summary>apparmor-profile: 6 affected resources</summary>

- `kv-e2e-mixed/Deployment/backend (api)`
- `kv-e2e-mixed/Deployment/cache (redis)`
- `kv-e2e-mixed/Deployment/database (postgres)`
- `kv-e2e-mixed/Deployment/frontend (nginx)`
- `kv-e2e-mixed/Deployment/partially-hardened-app (app)`
- `kv-e2e-mixed/Deployment/startup-web-app (web)`

</details>

<details>
<summary>capabilities-not-dropped: 6 affected resources</summary>

- `kv-e2e-mixed/Deployment/backend (api)`
- `kv-e2e-mixed/Deployment/cache (redis)`
- `kv-e2e-mixed/Deployment/database (postgres)`
- `kv-e2e-mixed/Deployment/frontend (nginx)`
- `kv-e2e-mixed/Deployment/partially-hardened-app (app)`
- `kv-e2e-mixed/Deployment/startup-web-app (web)`

</details>

<details>
<summary>image-pull-policy: 3 affected resources</summary>

- `kv-e2e-mixed/Deployment/backend (api)`
- `kv-e2e-mixed/Deployment/cache (redis)`
- `kv-e2e-mixed/Deployment/database (postgres)`

</details>

<details>
<summary>psa-restricted-violations: 17 affected resources</summary>

- `kv-e2e-mixed/Deployment/backend (api)`
- `kv-e2e-mixed/Deployment/backend (api)`
- `kv-e2e-mixed/Deployment/backend (api)`
- `kv-e2e-mixed/Deployment/cache (redis)`
- `kv-e2e-mixed/Deployment/cache (redis)`
- `kv-e2e-mixed/Deployment/cache (redis)`
- `kv-e2e-mixed/Deployment/database (postgres)`
- `kv-e2e-mixed/Deployment/database (postgres)`
- `kv-e2e-mixed/Deployment/database (postgres)`
- `kv-e2e-mixed/Deployment/frontend (nginx)`
- `kv-e2e-mixed/Deployment/frontend (nginx)`
- `kv-e2e-mixed/Deployment/frontend (nginx)`
- `kv-e2e-mixed/Deployment/partially-hardened-app (app)`
- `kv-e2e-mixed/Deployment/partially-hardened-app (app)`
- `kv-e2e-mixed/Deployment/startup-web-app (web)`
- `kv-e2e-mixed/Deployment/startup-web-app (web)`
- `kv-e2e-mixed/Deployment/startup-web-app (web)`

</details>

<details>
<summary>read-only-rootfs: 5 affected resources</summary>

- `kv-e2e-mixed/Deployment/backend (api)`
- `kv-e2e-mixed/Deployment/cache (redis)`
- `kv-e2e-mixed/Deployment/database (postgres)`
- `kv-e2e-mixed/Deployment/frontend (nginx)`
- `kv-e2e-mixed/Deployment/startup-web-app (web)`

</details>

<details>
<summary>run-as-group: 6 affected resources</summary>

- `kv-e2e-mixed/Deployment/backend (api)`
- `kv-e2e-mixed/Deployment/cache (redis)`
- `kv-e2e-mixed/Deployment/database (postgres)`
- `kv-e2e-mixed/Deployment/frontend (nginx)`
- `kv-e2e-mixed/Deployment/partially-hardened-app (app)`
- `kv-e2e-mixed/Deployment/startup-web-app (web)`

</details>

<details>
<summary>seccomp-profile: 6 affected resources</summary>

- `kv-e2e-mixed/Deployment/backend (api)`
- `kv-e2e-mixed/Deployment/cache (redis)`
- `kv-e2e-mixed/Deployment/database (postgres)`
- `kv-e2e-mixed/Deployment/frontend (nginx)`
- `kv-e2e-mixed/Deployment/partially-hardened-app (app)`
- `kv-e2e-mixed/Deployment/startup-web-app (web)`

</details>

<details>
<summary>token-projection-config: 6 affected resources</summary>

- `kv-e2e-mixed/Deployment/backend`
- `kv-e2e-mixed/Deployment/cache`
- `kv-e2e-mixed/Deployment/database`
- `kv-e2e-mixed/Deployment/frontend`
- `kv-e2e-mixed/Deployment/partially-hardened-app`
- `kv-e2e-mixed/Deployment/startup-web-app`

</details>

<details>
<summary>resource-limits-missing: 2 affected resources</summary>

- `kv-e2e-mixed/Deployment/cache (redis)`
- `kv-e2e-mixed/Deployment/startup-web-app (web)`

</details>

<details>
<summary>resource-requests-missing: 3 affected resources</summary>

- `kv-e2e-mixed/Deployment/cache (redis)`
- `kv-e2e-mixed/Deployment/partially-hardened-app (app)`
- `kv-e2e-mixed/Deployment/startup-web-app (web)`

</details>

<details>
<summary>image-tag-latest: 3 affected resources</summary>

- `kv-e2e-mixed/Deployment/frontend (nginx)`
- `kv-e2e-mixed/Deployment/partially-hardened-app (app)`
- `kv-e2e-mixed/Deployment/startup-web-app (web)`

</details>

<details>
<summary>ephemeral-storage-limits: 6 affected resources</summary>

- `kv-e2e-mixed/Deployment/backend (api)`
- `kv-e2e-mixed/Deployment/cache (redis)`
- `kv-e2e-mixed/Deployment/database (postgres)`
- `kv-e2e-mixed/Deployment/frontend (nginx)`
- `kv-e2e-mixed/Deployment/partially-hardened-app (app)`
- `kv-e2e-mixed/Deployment/startup-web-app (web)`

</details>

<details>
<summary>image-no-digest: 6 affected resources</summary>

- `kv-e2e-mixed/Deployment/backend (api)`
- `kv-e2e-mixed/Deployment/cache (redis)`
- `kv-e2e-mixed/Deployment/database (postgres)`
- `kv-e2e-mixed/Deployment/frontend (nginx)`
- `kv-e2e-mixed/Deployment/partially-hardened-app (app)`
- `kv-e2e-mixed/Deployment/startup-web-app (web)`

</details>

<details>
<summary>liveness-readiness-probes: 12 affected resources</summary>

- `kv-e2e-mixed/Deployment/backend (api)`
- `kv-e2e-mixed/Deployment/backend (api)`
- `kv-e2e-mixed/Deployment/cache (redis)`
- `kv-e2e-mixed/Deployment/cache (redis)`
- `kv-e2e-mixed/Deployment/database (postgres)`
- `kv-e2e-mixed/Deployment/database (postgres)`
- `kv-e2e-mixed/Deployment/frontend (nginx)`
- `kv-e2e-mixed/Deployment/frontend (nginx)`
- `kv-e2e-mixed/Deployment/partially-hardened-app (app)`
- `kv-e2e-mixed/Deployment/partially-hardened-app (app)`
- `kv-e2e-mixed/Deployment/startup-web-app (web)`
- `kv-e2e-mixed/Deployment/startup-web-app (web)`

</details>

<details>
<summary>pod-disruption-budget: 3 affected resources</summary>

- `kv-e2e-mixed/Deployment/backend`
- `kv-e2e-mixed/Deployment/frontend`
- `kv-e2e-mixed/Deployment/startup-web-app`

</details>

<details>
<summary>priority-class-missing: 6 affected resources</summary>

- `kv-e2e-mixed/Deployment/backend`
- `kv-e2e-mixed/Deployment/cache`
- `kv-e2e-mixed/Deployment/database`
- `kv-e2e-mixed/Deployment/frontend`
- `kv-e2e-mixed/Deployment/partially-hardened-app`
- `kv-e2e-mixed/Deployment/startup-web-app`

</details>

<details>
<summary>runtime-class: 6 affected resources</summary>

- `kv-e2e-mixed/Deployment/backend`
- `kv-e2e-mixed/Deployment/cache`
- `kv-e2e-mixed/Deployment/database`
- `kv-e2e-mixed/Deployment/frontend`
- `kv-e2e-mixed/Deployment/partially-hardened-app`
- `kv-e2e-mixed/Deployment/startup-web-app`

</details>

<details>
<summary>topology-spread: 6 affected resources</summary>

- `kv-e2e-mixed/Deployment/backend`
- `kv-e2e-mixed/Deployment/cache`
- `kv-e2e-mixed/Deployment/database`
- `kv-e2e-mixed/Deployment/frontend`
- `kv-e2e-mixed/Deployment/partially-hardened-app`
- `kv-e2e-mixed/Deployment/startup-web-app`

</details>

<details>
<summary>Remediation: automount-token (6 resources affected)</summary>

## Why This Matters

When a ServiceAccount token is auto-mounted, every container in the pod can call the Kubernetes API. If a container is compromised through a vulnerability or misconfiguration, the attacker gains API access to enumerate resources, read secrets, or escalate privileges.

## How to Fix

Disable auto-mounting at the pod spec level for workloads that do not need API access:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      automountServiceAccountToken: false
      containers:
        - name: app
          image: my-app:latest
```

For workloads that do require API access, use projected tokens with bounded lifetime and audience restrictions instead of the default long-lived token.

## Learn More

Refer to the Kubernetes documentation on configuring service accounts for pods and CIS Kubernetes Benchmark 5.1.6 for auto-mount token guidance.

**Affected resources:** kv-e2e-mixed/Deployment/backend, kv-e2e-mixed/Deployment/cache, kv-e2e-mixed/Deployment/database, kv-e2e-mixed/Deployment/frontend, kv-e2e-mixed/Deployment/partially-hardened-app, kv-e2e-mixed/Deployment/startup-web-app

</details>

<details>
<summary>Remediation: capabilities-added (1 resources affected)</summary>

## Why This Matters

Linux capabilities like SYS_ADMIN, NET_RAW, and SYS_PTRACE grant kernel-level powers that dramatically expand a container's attack surface. SYS_ADMIN alone enables filesystem mounts and namespace manipulation that can lead to container escape. NET_RAW allows ARP spoofing and network sniffing attacks within the cluster.

## How to Fix

Drop all capabilities and only add back the specific ones your application truly requires:

```yaml
securityContext:
  capabilities:
    drop: ["ALL"]
    add: []  # Only add specific caps after careful review
```

If your application needs to bind to ports below 1024, consider using a Kubernetes Service instead of granting NET_BIND_SERVICE. If setup tasks need elevated permissions, use an init container.

## Learn More

The Pod Security Standards "Restricted" profile only allows NET_BIND_SERVICE. Refer to the Linux capabilities man page (capabilities(7)) and CIS Benchmark 5.2.7-5.2.9 for guidance on acceptable capabilities.

**Affected resources:** kv-e2e-mixed/Deployment/backend

</details>

<details>
<summary>Remediation: default-service-account (5 resources affected)</summary>

## Why This Matters

The default ServiceAccount is shared by every pod in a namespace. If any pod is compromised, the attacker inherits whatever permissions have been granted to the default account via role bindings, enabling lateral movement across all workloads sharing it.

## How to Fix

Create a dedicated ServiceAccount for each workload and reference it in the pod spec:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-app
  namespace: production
automountServiceAccountToken: false
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      serviceAccountName: my-app
```

Grant only the permissions the workload actually needs via a dedicated Role and RoleBinding.

## Learn More

See the Kubernetes documentation on managing service accounts and CIS Kubernetes Benchmark 5.1.5 for guidance on ensuring default service accounts are not actively used.

**Affected resources:** kv-e2e-mixed/Deployment/backend, kv-e2e-mixed/Deployment/cache, kv-e2e-mixed/Deployment/database, kv-e2e-mixed/Deployment/frontend, kv-e2e-mixed/Deployment/startup-web-app

</details>

<details>
<summary>Remediation: privilege-escalation (6 resources affected)</summary>

## Why This Matters

By default, Kubernetes allows containers to escalate privileges via setuid/setgid binaries, which let a process gain more permissions than its parent. An attacker can exploit this using setuid binaries already present in the container image (like `su`, `sudo`, or `ping`) to elevate from a low-privilege user to root.

## How to Fix

Explicitly disable privilege escalation in the container's securityContext:

```yaml
securityContext:
  allowPrivilegeEscalation: false
  runAsNonRoot: true
  capabilities:
    drop: ["ALL"]
```

This blocks the use of setuid/setgid binaries and prevents the no_new_privs Linux flag from being cleared. The vast majority of application containers do not need privilege escalation.

## Learn More

This is required by the Pod Security Standards "Restricted" profile and CIS Benchmark 5.2.5. Disabling privilege escalation is one of the most impactful single-line security improvements you can make.

**Affected resources:** kv-e2e-mixed/Deployment/backend, kv-e2e-mixed/Deployment/cache, kv-e2e-mixed/Deployment/database, kv-e2e-mixed/Deployment/frontend, kv-e2e-mixed/Deployment/partially-hardened-app, kv-e2e-mixed/Deployment/startup-web-app

</details>

<details>
<summary>Remediation: run-as-root (5 resources affected)</summary>

## Why This Matters

Without `runAsNonRoot: true`, Kubernetes does not enforce non-root execution and the container may default to running as UID 0 depending on the image's USER directive. If the image defaults to root, the container process gains full privileges, increasing the blast radius of any compromise or container escape.

## How to Fix

Enforce non-root execution in the securityContext:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
```

With `runAsNonRoot: true`, Kubernetes will reject the pod at admission time if the container image attempts to run as root. Setting an explicit `runAsUser` provides an additional guarantee.

## Learn More

This aligns with CIS Benchmark 5.2.6 and the Pod Security Standards "Restricted" profile. The `runAsNonRoot` field acts as a safety net even when images change their default USER.

**Affected resources:** kv-e2e-mixed/Deployment/backend, kv-e2e-mixed/Deployment/cache, kv-e2e-mixed/Deployment/frontend, kv-e2e-mixed/Deployment/partially-hardened-app, kv-e2e-mixed/Deployment/startup-web-app

</details>

<details>
<summary>Remediation: host-ports (1 resources affected)</summary>

## Why This Matters

Binding to a host port exposes your service directly on the node's network interface, bypassing Kubernetes Service abstractions and NetworkPolicies. It also ties each pod replica to a unique node (since two pods cannot share the same host port), severely limiting scheduling flexibility, rolling updates, and scaling.

## How to Fix

Remove the hostPort and use Kubernetes Services to expose your application:

```yaml
ports:
  - containerPort: 8080
    protocol: TCP
    # Remove hostPort entirely
```

Use a ClusterIP Service for internal traffic, NodePort or LoadBalancer for external access, or an Ingress controller for HTTP routing.

## Learn More

Host ports are prohibited by the Pod Security Standards "Baseline" profile. The only common legitimate use is for DaemonSets that must bind to a well-known port on every node (e.g., log collectors).

**Affected resources:** kv-e2e-mixed/Deployment/cache

</details>

<details>
<summary>Remediation: network-policy-default-deny (2 resources affected)</summary>

## Why This Matters

Without a default-deny ingress policy, all inbound traffic to pods is allowed by default. An attacker who gains access to any pod in the cluster can reach services in this namespace, enabling lateral movement and data theft.

## How to Fix

Create a default-deny ingress NetworkPolicy that selects all pods, then add specific allow rules for legitimate traffic:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: my-namespace
spec:
  podSelector: {}
  policyTypes:
    - Ingress
```

Then create additional policies with explicit `ingress.from` rules for each service that needs to receive traffic.

## Learn More

Refer to the Kubernetes NetworkPolicy documentation and CIS Kubernetes Benchmark 5.3.2. Default-deny is a zero-trust network best practice recommended by the NSA/CISA Kubernetes Hardening Guide.

**Affected resources:** kv-e2e-mixed/Namespace/kv-e2e-mixed, kv-e2e-mixed/Namespace/kv-e2e-mixed

</details>

<details>
<summary>Remediation: apparmor-profile (6 resources affected)</summary>

## Why This Matters

AppArmor provides mandatory access control (MAC) that restricts which files, network resources, and capabilities a container process can access. Without an AppArmor profile, the container operates without these restrictions, allowing an attacker with code execution to access any file the container user can read and make unrestricted network connections.

## How to Fix

Apply an AppArmor profile in the container's securityContext (Kubernetes 1.30+):

```yaml
securityContext:
  appArmorProfile:
    type: RuntimeDefault
```

The RuntimeDefault profile provides sensible restrictions for most applications. For tighter control, create a custom Localhost profile that only allows the specific file and network access your application needs.

## Learn More

AppArmor is available on Debian/Ubuntu-based nodes. RHEL/CentOS nodes use SELinux instead. Both provide MAC enforcement. Refer to CIS Benchmark 5.7.5 and the Kubernetes AppArmor documentation.

**Affected resources:** kv-e2e-mixed/Deployment/backend, kv-e2e-mixed/Deployment/cache, kv-e2e-mixed/Deployment/database, kv-e2e-mixed/Deployment/frontend, kv-e2e-mixed/Deployment/partially-hardened-app, kv-e2e-mixed/Deployment/startup-web-app

</details>

<details>
<summary>Remediation: capabilities-not-dropped (6 resources affected)</summary>

## Why This Matters

By default, containers receive a set of Linux capabilities including KILL, SETUID, SETGID, and NET_RAW. These defaults are rarely needed by application code and significantly increase the potential damage from a container compromise. Dropping all capabilities follows the principle of least privilege.

## How to Fix

Explicitly drop all capabilities and selectively add back only what your application needs:

```yaml
securityContext:
  capabilities:
    drop: ["ALL"]
    add: ["NET_BIND_SERVICE"]  # Only if needed
```

Most web applications, API servers, and background workers run perfectly with all capabilities dropped. Test your application after making this change to confirm no functionality is lost.

## Learn More

This is required by the Pod Security Standards "Restricted" profile and aligns with CIS Benchmark 5.2.7. Kubernetes best practice is to treat capability grants as exceptions that require explicit justification.

**Affected resources:** kv-e2e-mixed/Deployment/backend, kv-e2e-mixed/Deployment/cache, kv-e2e-mixed/Deployment/database, kv-e2e-mixed/Deployment/frontend, kv-e2e-mixed/Deployment/partially-hardened-app, kv-e2e-mixed/Deployment/startup-web-app

</details>

<details>
<summary>Remediation: image-pull-policy (3 resources affected)</summary>

## Why This Matters

When a mutable image tag is used without `imagePullPolicy: Always`, Kubernetes may serve a cached version of the image from the node. If the tag has been updated in the registry (with a security patch or -- worse -- a compromised layer), the running container will not reflect those changes.

## How to Fix

Set `imagePullPolicy: Always` for any container using a mutable tag:

```yaml
containers:
  - name: app
    image: nginx:1.25.3
    imagePullPolicy: Always   # Forces fresh pull each time
```

Alternatively, pin images by digest (`image@sha256:...`), which makes the pull policy irrelevant because the content is immutable.

## Learn More

See the Kubernetes documentation on image pull policies and CIS Kubernetes Benchmark 5.4.2 for pull policy guidance.

**Affected resources:** kv-e2e-mixed/Deployment/backend, kv-e2e-mixed/Deployment/cache, kv-e2e-mixed/Deployment/database

</details>

<details>
<summary>Remediation: psa-restricted-violations (17 resources affected)</summary>

## Why This Matters

Running as root inside a container means that any container escape vulnerability immediately grants root access on the host node. Even without an escape, root inside the container can modify sensitive files, install packages, and access capabilities that non-root users cannot.

## How to Fix

Set `runAsNonRoot: true` and specify a non-root user ID in the security context:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
```

Set this at the pod level to apply to all containers. Ensure your container image supports running as a non-root user (many official images do).

## Learn More

See the Pod Security Standards Restricted profile and CIS Kubernetes Benchmark 5.2.6. Running as non-root is a fundamental container security best practice.

**Affected resources:** kv-e2e-mixed/Deployment/backend, kv-e2e-mixed/Deployment/backend, kv-e2e-mixed/Deployment/backend, kv-e2e-mixed/Deployment/cache, kv-e2e-mixed/Deployment/cache, kv-e2e-mixed/Deployment/cache, kv-e2e-mixed/Deployment/database, kv-e2e-mixed/Deployment/database, kv-e2e-mixed/Deployment/database, kv-e2e-mixed/Deployment/frontend, kv-e2e-mixed/Deployment/frontend, kv-e2e-mixed/Deployment/frontend, kv-e2e-mixed/Deployment/partially-hardened-app, kv-e2e-mixed/Deployment/partially-hardened-app, kv-e2e-mixed/Deployment/startup-web-app, kv-e2e-mixed/Deployment/startup-web-app, kv-e2e-mixed/Deployment/startup-web-app

</details>

<details>
<summary>Remediation: read-only-rootfs (5 resources affected)</summary>

## Why This Matters

A writable root filesystem allows an attacker who gains code execution in your container to modify application binaries, install attack tools, plant backdoors, or persist malware across container restarts. Making the filesystem read-only eliminates an entire class of post-exploitation techniques.

## How to Fix

Enable a read-only root filesystem and mount writable volumes only where needed:

```yaml
securityContext:
  readOnlyRootFilesystem: true
volumeMounts:
  - name: tmp
    mountPath: /tmp
volumes:
  - name: tmp
    emptyDir: {}
```

Common paths that need write access include /tmp, /var/cache, and /var/run. Mount each as an emptyDir or tmpfs volume rather than making the entire filesystem writable.

## Learn More

This aligns with CIS Benchmark 5.2.4 and the defense-in-depth principle. Combined with dropping capabilities and running as non-root, a read-only filesystem forms a strong container hardening baseline.

**Affected resources:** kv-e2e-mixed/Deployment/backend, kv-e2e-mixed/Deployment/cache, kv-e2e-mixed/Deployment/database, kv-e2e-mixed/Deployment/frontend, kv-e2e-mixed/Deployment/startup-web-app

</details>

<details>
<summary>Remediation: run-as-group (6 resources affected)</summary>

## Why This Matters

Without an explicit runAsGroup, the container process defaults to GID 0 (the root group). Files and sockets owned by the root group become accessible to the container, including potentially sensitive host files if volumes are mounted. This widens the attack surface unnecessarily.

## How to Fix

Set an explicit non-root group in the securityContext:

```yaml
securityContext:
  runAsGroup: 1000
  runAsUser: 1000
  runAsNonRoot: true
```

Ensure the container image's application files and directories are readable by the specified GID. You may need to adjust file ownership in your Dockerfile with `chown`.

## Learn More

This aligns with CIS Benchmark 5.2.6 and the Pod Security Standards "Restricted" profile. Always set runAsUser, runAsGroup, and runAsNonRoot together for comprehensive identity control.

**Affected resources:** kv-e2e-mixed/Deployment/backend, kv-e2e-mixed/Deployment/cache, kv-e2e-mixed/Deployment/database, kv-e2e-mixed/Deployment/frontend, kv-e2e-mixed/Deployment/partially-hardened-app, kv-e2e-mixed/Deployment/startup-web-app

</details>

<details>
<summary>Remediation: seccomp-profile (6 resources affected)</summary>

## Why This Matters

Without a Seccomp profile, containers can invoke any of the 300+ Linux system calls, leaving the entire kernel attack surface exposed. Kernel vulnerabilities in obscure syscalls are a primary vector for container escapes. Seccomp filtering blocks dangerous syscalls that legitimate applications never use.

## How to Fix

Apply a Seccomp profile at the container or pod level:

```yaml
securityContext:
  seccompProfile:
    type: RuntimeDefault
```

The RuntimeDefault profile blocks approximately 50 dangerous syscalls while allowing normal application behavior. For stricter controls, use a custom Localhost profile tailored to your application's needs. Set the profile at the pod level to apply it to all containers.

## Learn More

Seccomp profiles are required by the Pod Security Standards "Restricted" profile and CIS Benchmark 5.7.2. Use tools like `strace` or the Security Profiles Operator to generate custom profiles for your workloads.

**Affected resources:** kv-e2e-mixed/Deployment/backend, kv-e2e-mixed/Deployment/cache, kv-e2e-mixed/Deployment/database, kv-e2e-mixed/Deployment/frontend, kv-e2e-mixed/Deployment/partially-hardened-app, kv-e2e-mixed/Deployment/startup-web-app

</details>

<details>
<summary>Remediation: secrets-in-env (1 resources affected)</summary>

## Why This Matters

Environment variables are visible in pod specs, process listings (`/proc/*/environ`), crash dumps, and log output. They are also inherited by child processes. If a secret leaks through any of these channels, an attacker gains immediate access to the credential.

## How to Fix

Mount secrets as files using a volume instead of environment variables:

```yaml
volumeMounts:
  - name: secret-vol
    mountPath: /etc/secrets
    readOnly: true
volumes:
  - name: secret-vol
    secret:
      secretName: my-secret
```

File-mounted secrets are stored on tmpfs, are not exposed in logs or process listings, and support automatic rotation via the kubelet.

## Learn More

CIS Kubernetes Benchmark 5.4.1 and NSA/CISA Kubernetes Hardening Guide recommend avoiding secrets in environment variables. See the Kubernetes Secrets documentation for volume mount examples.

**Affected resources:** kv-e2e-mixed/Deployment/backend

</details>

<details>
<summary>Remediation: token-projection-config (6 resources affected)</summary>

## Why This Matters

Without explicit projection configuration, ServiceAccount tokens use Kubernetes defaults: no audience restriction and a long expiration. A stolen token remains valid for an extended period and can be used against any API server endpoint, widening the blast radius of a compromise.

## How to Fix

Add a projected volume with explicit expiration and audience:

```yaml
spec:
  volumes:
    - name: token
      projected:
        sources:
          - serviceAccountToken:
              expirationSeconds: 3600
              audience: my-api
              path: token
  containers:
    - name: app
      volumeMounts:
        - name: token
          mountPath: /var/run/secrets/tokens
          readOnly: true
```

Projected tokens auto-rotate before expiry and are rejected by endpoints outside the specified audience.

## Learn More

See the Kubernetes documentation on projected volumes and service account token volume projection for detailed configuration options.

**Affected resources:** kv-e2e-mixed/Deployment/backend, kv-e2e-mixed/Deployment/cache, kv-e2e-mixed/Deployment/database, kv-e2e-mixed/Deployment/frontend, kv-e2e-mixed/Deployment/partially-hardened-app, kv-e2e-mixed/Deployment/startup-web-app

</details>

<details>
<summary>Remediation: resource-limits-missing (2 resources affected)</summary>

## Why This Matters

Without resource limits, a single container can consume all available CPU and memory on a node, starving other workloads and triggering cascading failures. An attacker who compromises an unlimited container can mount a denial-of-service attack against the entire node with a simple fork bomb or memory allocation loop.

## How to Fix

Set both CPU and memory limits based on your application's actual resource usage:

```yaml
resources:
  limits:
    cpu: 500m
    memory: 256Mi
  requests:
    cpu: 100m
    memory: 128Mi
```

Profile your application under load to determine appropriate values. Set limits to handle peak usage and requests to match steady-state consumption.

## Learn More

Use LimitRange objects to enforce default limits at the namespace level. Resource limits also determine the pod's QoS class: pods with equal requests and limits get Guaranteed QoS and are last to be evicted.

**Affected resources:** kv-e2e-mixed/Deployment/cache, kv-e2e-mixed/Deployment/startup-web-app

</details>

<details>
<summary>Remediation: resource-requests-missing (3 resources affected)</summary>

## Why This Matters

Resource requests tell the Kubernetes scheduler how much CPU and memory your container needs. Without requests, the scheduler treats the pod as needing zero resources and may pack too many pods onto a single node. This leads to overcommitment, resource contention, throttling, and OOM kills under load.

## How to Fix

Set resource requests based on your application's steady-state usage:

```yaml
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 256Mi
```

Observe your application's actual resource consumption using `kubectl top` or a monitoring tool, then set requests to match the typical steady-state usage.

## Learn More

Resource requests determine the pod's QoS class and scheduling behavior. Pods with requests equal to limits receive Guaranteed QoS. Use Vertical Pod Autoscaler (VPA) to automatically recommend request values.

**Affected resources:** kv-e2e-mixed/Deployment/cache, kv-e2e-mixed/Deployment/partially-hardened-app, kv-e2e-mixed/Deployment/startup-web-app

</details>

<details>
<summary>Remediation: host-path-volumes (1 resources affected)</summary>

## Why This Matters

hostPath volumes give containers direct, unrestricted access to the host node's filesystem. Depending on the path mounted, an attacker can read sensitive host files (/etc/shadow), access container runtime sockets for escape, or modify system binaries. This is one of the most common paths to full node compromise.

## How to Fix

Replace hostPath volumes with safer alternatives:

```yaml
volumes:
  - name: data
    emptyDir: {}          # Pod-scoped temporary storage
  - name: persistent
    persistentVolumeClaim:
      claimName: my-pvc  # Managed storage
```

If host filesystem access is absolutely required (e.g., for log collectors or node monitoring), mount the most restrictive path possible and set `readOnly: true` in the volumeMount.

## Learn More

hostPath volumes are prohibited in the Pod Security Standards "Baseline" profile. Refer to CIS Benchmark 5.2.13 and use PersistentVolumeClaims with CSI drivers for production data storage needs.

**Affected resources:** kv-e2e-mixed/Deployment/database

</details>

<details>
<summary>Remediation: image-tag-latest (3 resources affected)</summary>

## Why This Matters

The :latest tag is mutable and can resolve to a different image at any time. Deployments become non-reproducible, rollbacks break silently, and attackers can poison the tag to inject malicious code without changing your manifests.

## How to Fix

Pin every container image to a specific, immutable version tag:

```yaml
containers:
  - name: app
    image: nginx:1.25.3          # Pinned version tag
    # Or pin by digest for maximum immutability:
    # image: nginx@sha256:a8281ce42034
```

Adopt a CI/CD practice of updating image tags via automated PRs so manifests always reflect the exact version deployed.

## Learn More

The CIS Kubernetes Benchmark 5.4.1 recommends pinning image versions. See the Kubernetes documentation on container images for tag best practices.

**Affected resources:** kv-e2e-mixed/Deployment/frontend, kv-e2e-mixed/Deployment/partially-hardened-app, kv-e2e-mixed/Deployment/startup-web-app

</details>

<details>
<summary>Remediation: network-policy-egress-unrestricted (1 resources affected)</summary>

## Why This Matters

Without any egress NetworkPolicy in this namespace, pods can freely send traffic to any destination including the public internet. A compromised pod can exfiltrate sensitive data, reach cloud metadata services (e.g., 169.254.169.254), or establish reverse shells to attacker-controlled servers.

## How to Fix

Create a NetworkPolicy with `Egress` in `policyTypes` to restrict outbound traffic. At minimum, allow DNS resolution:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-egress
  namespace: my-namespace
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector: {}
      ports:
        - port: 53
          protocol: UDP
```

Add additional egress rules for specific services your workloads need to reach.

## Learn More

See the Kubernetes NetworkPolicy documentation and CIS Kubernetes Benchmark 5.3.2. Egress controls are a key defense-in-depth measure recommended by the NSA/CISA Kubernetes Hardening Guide.

**Affected resources:** kv-e2e-mixed/Namespace/kv-e2e-mixed

</details>

<details>
<summary>Remediation: psa-labels-missing (1 resources affected)</summary>

## Why This Matters

Without PSA enforcement labels, any pod configuration is allowed in this namespace, including privileged containers, host namespace access, and root execution. This bypasses Kubernetes' built-in Pod Security Standards and leaves the namespace vulnerable to workloads that could compromise the node.

## How to Fix

Add Pod Security Admission labels to enforce a security profile on all pods in the namespace:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: kv-e2e-mixed
  labels:
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

Start with `baseline` enforcement to block known privilege escalations, then upgrade to `restricted` after verifying all workloads are compliant.

## Learn More

See the Kubernetes Pod Security Admission documentation and CIS Kubernetes Benchmark 5.2. The three-tier approach (enforce, audit, warn) allows gradual adoption of stricter profiles.

**Affected resources:** kv-e2e-mixed/Namespace/kv-e2e-mixed

</details>

<details>
<summary>Remediation: network-policy-overly-permissive (1 resources affected)</summary>

## Why This Matters

This NetworkPolicy allows ingress traffic from any source, which is equivalent to having no ingress restriction at all. An attacker who compromises any pod in the cluster can reach services protected by this policy, defeating the purpose of network segmentation.

## How to Fix

Replace the permissive rule with specific source selectors that limit traffic to known, trusted origins:

```yaml
spec:
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: frontend
        - namespaceSelector:
            matchLabels:
              env: production
      ports:
        - port: 8080
          protocol: TCP
```

For external sources, use `ipBlock` with specific CIDRs and `except` ranges to narrow allowed IP ranges.

## Learn More

Refer to the Kubernetes NetworkPolicy documentation on ingress rules. CIS Kubernetes Benchmark 5.3.2 recommends ensuring that all namespaces have appropriately restrictive network policies.

**Affected resources:** kv-e2e-mixed/NetworkPolicy/partially-hardened-policy

</details>

<details>
<summary>Remediation: ephemeral-storage-limits (6 resources affected)</summary>

## Why This Matters

Ephemeral storage includes container logs, emptyDir volumes, and the writable container layer. Without limits, a single container can fill the node's root disk, triggering eviction of all pods on that node and potentially causing a cascading failure across your cluster. This is a common denial-of-service vector.

## How to Fix

Set ephemeral-storage limits alongside your CPU and memory limits:

```yaml
resources:
  limits:
    ephemeral-storage: 1Gi
  requests:
    ephemeral-storage: 500Mi
```

Estimate your application's disk usage from logs, temporary files, and cache data. If your application writes large temporary files, consider using a PersistentVolumeClaim instead of ephemeral storage.

## Learn More

The kubelet evicts pods that exceed their ephemeral-storage limit. Use LimitRange to set default ephemeral-storage limits at the namespace level to catch containers that omit this setting.

**Affected resources:** kv-e2e-mixed/Deployment/backend, kv-e2e-mixed/Deployment/cache, kv-e2e-mixed/Deployment/database, kv-e2e-mixed/Deployment/frontend, kv-e2e-mixed/Deployment/partially-hardened-app, kv-e2e-mixed/Deployment/startup-web-app

</details>

<details>
<summary>Remediation: image-no-digest (6 resources affected)</summary>

## Why This Matters

Image tags are mutable pointers -- a registry administrator or attacker can re-push a different image under the same tag. Without a digest, you have no cryptographic guarantee that the image you deploy is the one you tested.

## How to Fix

Pin images by their SHA-256 content digest for a fully immutable reference:

```yaml
containers:
  - name: app
    image: nginx@sha256:a8281ce420348a01ea6e   # Immutable
```

Use `crane digest nginx:1.25.3` or `skopeo inspect` to resolve a tag to its digest during CI/CD, then commit the pinned reference.

## Learn More

SLSA Level 1+ and NIST SP 800-190 recommend digest pinning for container supply chain integrity. See the Kubernetes images documentation for details.

**Affected resources:** kv-e2e-mixed/Deployment/backend, kv-e2e-mixed/Deployment/cache, kv-e2e-mixed/Deployment/database, kv-e2e-mixed/Deployment/frontend, kv-e2e-mixed/Deployment/partially-hardened-app, kv-e2e-mixed/Deployment/startup-web-app

</details>

<details>
<summary>Remediation: liveness-readiness-probes (12 resources affected)</summary>

## Why This Matters

Without a liveness probe, Kubernetes cannot detect when a container has become unresponsive or deadlocked. The container continues running and consuming resources while failing to serve traffic. Users experience timeouts and errors until someone manually intervenes.

## How to Fix

Add a liveness probe that checks the container's health:

```yaml
containers:
  - name: app
    livenessProbe:
      httpGet:
        path: /healthz
        port: 8080
      initialDelaySeconds: 15
      periodSeconds: 10
      failureThreshold: 3
```

Use `httpGet` for HTTP services, `tcpSocket` for TCP services, or `exec` with a custom health check script for non-network workloads.

## Learn More

See the Kubernetes documentation on container probes. Set initialDelaySeconds high enough for your application to start, and consider adding a startupProbe for slow-starting containers.

**Affected resources:** kv-e2e-mixed/Deployment/backend, kv-e2e-mixed/Deployment/backend, kv-e2e-mixed/Deployment/cache, kv-e2e-mixed/Deployment/cache, kv-e2e-mixed/Deployment/database, kv-e2e-mixed/Deployment/database, kv-e2e-mixed/Deployment/frontend, kv-e2e-mixed/Deployment/frontend, kv-e2e-mixed/Deployment/partially-hardened-app, kv-e2e-mixed/Deployment/partially-hardened-app, kv-e2e-mixed/Deployment/startup-web-app, kv-e2e-mixed/Deployment/startup-web-app

</details>

<details>
<summary>Remediation: pod-disruption-budget (3 resources affected)</summary>

## Why This Matters

Without a PodDisruptionBudget, Kubernetes can evict all replicas of your workload simultaneously during voluntary disruptions like node drains, cluster upgrades, or autoscaler scale-downs. This causes complete service downtime even though you have multiple replicas.

## How to Fix

Create a PodDisruptionBudget that matches your workload's pod labels:

```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: my-app-pdb
spec:
  minAvailable: 1              # Or use maxUnavailable: 1
  selector:
    matchLabels:
      app: my-app              # Must match your Deployment/StatefulSet pod labels
```

Use `minAvailable` to guarantee a minimum number of running pods, or `maxUnavailable` to limit how many can be down at once.

## Learn More

See the Kubernetes PodDisruptionBudget documentation for details on voluntary disruption handling. PDBs are essential for production workloads that need high availability during cluster maintenance.

**Affected resources:** kv-e2e-mixed/Deployment/backend, kv-e2e-mixed/Deployment/frontend, kv-e2e-mixed/Deployment/startup-web-app

</details>

<details>
<summary>Remediation: priority-class-missing (6 resources affected)</summary>

## Why This Matters

Without a PriorityClass, pods receive default priority (typically 0) and are among the first to be evicted during resource pressure or node maintenance. This means important application workloads may be killed before less critical ones, leading to unpredictable outages.

## How to Fix

Define PriorityClasses for your workloads and assign them appropriately:

```yaml
apiVersion: scheduling.k8s.io/v1
kind: PriorityClass
metadata:
  name: app-medium
value: 100000
---
# Reference in your workload:
spec:
  priorityClassName: app-medium
```

Create a tiered priority scheme (e.g., app-critical: 500000, app-medium: 100000, app-low: 10000) that reflects your workload importance hierarchy.

## Learn More

Refer to the Kubernetes Pod Priority and Preemption documentation. Establishing a consistent priority scheme across namespaces ensures predictable eviction behavior during resource contention.

**Affected resources:** kv-e2e-mixed/Deployment/backend, kv-e2e-mixed/Deployment/cache, kv-e2e-mixed/Deployment/database, kv-e2e-mixed/Deployment/frontend, kv-e2e-mixed/Deployment/partially-hardened-app, kv-e2e-mixed/Deployment/startup-web-app

</details>

<details>
<summary>Remediation: runtime-class (6 resources affected)</summary>

## Why This Matters

Without a RuntimeClass, pods use the default container runtime (typically runc), which shares the host kernel directly with containers. A kernel vulnerability can allow container escape to the host. Sandboxed runtimes like gVisor or Kata Containers add an additional isolation layer that intercepts system calls or runs containers in lightweight VMs.

## How to Fix

Specify a sandboxed RuntimeClass in the pod spec:

```yaml
spec:
  runtimeClassName: gvisor
```

Available RuntimeClasses depend on your cluster configuration. Common options include `gvisor` (user-space kernel), `kata` (micro-VMs), and `firecracker`. Check your cluster's available RuntimeClasses with `kubectl get runtimeclasses`.

## Learn More

Sandboxed runtimes are especially important for multi-tenant clusters and workloads processing untrusted input. They add latency overhead, so evaluate performance requirements. See the Kubernetes RuntimeClass documentation.

**Affected resources:** kv-e2e-mixed/Deployment/backend, kv-e2e-mixed/Deployment/cache, kv-e2e-mixed/Deployment/database, kv-e2e-mixed/Deployment/frontend, kv-e2e-mixed/Deployment/partially-hardened-app, kv-e2e-mixed/Deployment/startup-web-app

</details>

<details>
<summary>Remediation: topology-spread (6 resources affected)</summary>

## Why This Matters

Without topology spread constraints, the scheduler may place all replicas on the same node or in the same availability zone. If that node or zone fails, your entire service goes down despite having multiple replicas. This negates the high-availability benefits of running multiple pods.

## How to Fix

Add topology spread constraints to distribute replicas across failure domains:

```yaml
spec:
  topologySpreadConstraints:
    - maxSkew: 1
      topologyKey: kubernetes.io/hostname
      whenUnsatisfiable: DoNotSchedule
      labelSelector:
        matchLabels:
          app: my-app
    - maxSkew: 1
      topologyKey: topology.kubernetes.io/zone
      whenUnsatisfiable: ScheduleAnyway
```

Use `kubernetes.io/hostname` for node-level spreading and `topology.kubernetes.io/zone` for zone-level spreading.

## Learn More

See the Kubernetes Pod Topology Spread Constraints documentation. Combining hostname and zone constraints provides both node-level and zone-level fault tolerance.

**Affected resources:** kv-e2e-mixed/Deployment/backend, kv-e2e-mixed/Deployment/cache, kv-e2e-mixed/Deployment/database, kv-e2e-mixed/Deployment/frontend, kv-e2e-mixed/Deployment/partially-hardened-app, kv-e2e-mixed/Deployment/startup-web-app

</details>

<details>
<summary>Remediation: run-as-high-uid (1 resources affected)</summary>

## Why This Matters

UIDs below 10000 overlap with well-known system accounts on most Linux distributions (e.g., daemon, www-data, nobody). If a container running with a low UID escapes to the host, it may inherit the permissions of that system account, gaining unintended access to host files, sockets, or services owned by that UID.

## How to Fix

Use a high UID that does not overlap with host system accounts:

```yaml
securityContext:
  runAsUser: 65534       # nobody, or any UID >= 10000
  runAsNonRoot: true
  runAsGroup: 65534
```

Choose a UID >= 10000. The conventional `nobody` UID (65534) is a safe default. Also set the UID in your Dockerfile with `USER 65534` for defense in depth.

## Learn More

This is a defense-in-depth measure. While container UID mapping varies by runtime, using high UIDs avoids accidental privilege overlap on hosts that lack user namespace remapping.

**Affected resources:** kv-e2e-mixed/Deployment/database

</details>

<details>
<summary>Remediation: limit-range-missing (1 resources affected)</summary>

## Why This Matters

Without a LimitRange, any container can be created without resource constraints. A single runaway or malicious pod can consume all node CPU and memory, causing denial of service for other workloads on the same node.

## How to Fix

Create a LimitRange in the namespace to set default and maximum resource constraints:

```yaml
apiVersion: v1
kind: LimitRange
metadata:
  name: default-limits
  namespace: my-app
spec:
  limits:
    - type: Container
      default:
        cpu: 500m
        memory: 256Mi
      defaultRequest:
        cpu: 100m
        memory: 128Mi
      max:
        cpu: "2"
        memory: 1Gi
```

Containers that omit resource requests/limits will inherit these defaults automatically.

## Learn More

CIS Kubernetes Benchmark 5.2.1 recommends LimitRanges for resource governance. See https://kubernetes.io/docs/concepts/policy/limit-range/ for configuration details.

**Affected resources:** kv-e2e-mixed/Namespace/kv-e2e-mixed

</details>

<details>
<summary>Remediation: resource-quota-missing (1 resources affected)</summary>

## Why This Matters

Without a ResourceQuota, a single namespace can consume the entire cluster's CPU, memory, and storage. This creates a noisy-neighbor problem where one team's workloads starve others, and makes capacity planning impossible.

## How to Fix

Create a ResourceQuota to cap the namespace's total resource consumption:

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: compute-quota
  namespace: my-app
spec:
  hard:
    requests.cpu: "10"
    requests.memory: 20Gi
    limits.cpu: "20"
    limits.memory: 40Gi
    pods: "50"
    services: "10"
```

Tune quota values based on the namespace's actual workload requirements and cluster capacity.

## Learn More

CIS Kubernetes Benchmark 5.2.2 recommends ResourceQuotas for multi-tenant clusters. See https://kubernetes.io/docs/concepts/policy/resource-quotas/ for quota configuration and enforcement behavior.

**Affected resources:** kv-e2e-mixed/Namespace/kv-e2e-mixed

</details>

<details>
<summary>Remediation: emptydir-size-limit (1 resources affected)</summary>

## Why This Matters

An emptyDir volume without a sizeLimit allows a container to write unlimited data to the node's filesystem. A compromised or misbehaving container can fill the entire node disk, causing kubelet failures, pod evictions, and node instability that affects all workloads on that node.

## How to Fix

Set a sizeLimit on the emptyDir volume based on expected usage:

```yaml
spec:
  volumes:
    - name: tmp
      emptyDir:
        sizeLimit: 1Gi           # Set to expected max usage
        medium: ""               # Or Memory for tmpfs
```

When the limit is exceeded, the pod will be evicted. Size conservatively and monitor actual usage to tune the limit.

## Learn More

See the Kubernetes Volumes documentation on emptyDir. Setting sizeLimit is a defense-in-depth measure that protects node stability alongside resource quotas and LimitRanges.

**Affected resources:** kv-e2e-mixed/Deployment/partially-hardened-app

</details>

### kv-e2e-network (41 findings — 🟠10 🟡19 🔵12)

| Severity | Check | Resources | Message | Frameworks |
|----------|-------|-----------|---------|-----------|
| 🟠 High | external-ips | kv-e2e-network/Service/hijack-svc | Service "hijack-svc" has externalIPs [198.51.100.10, 203.0.113.20] configured, posing a man-in-the-middle risk (CVE-2020-8554). | CIS 5.3.2 · MITRE T1190 · NSA 4.1 |
| 🟠 High | network-policy-default-deny | **2 resources** | Namespace "kv-e2e-network" is missing a default-deny ingress NetworkPolicy. | CIS 5.3.2 · MITRE T1046 · MITRE T1071 · NSA 4.2 |
| 🟠 High | ingress-no-tls | **3 resources** | Ingress "no-class-ingress" has no TLS configured. Traffic is served over unencrypted HTTP. | CIS 5.3.2 · MITRE T1040 · MITRE T1557 · NSA 4.3 |
| 🟠 High | automount-token | kv-e2e-network/Deployment/pause-app | Deployment "pause-app" auto-mounts a ServiceAccount token. Most workloads do not need Kubernetes API access. | CIS 5.1.6 · MITRE T1552.007 · NSA 3.2 |
| 🟠 High | default-service-account | kv-e2e-network/Deployment/pause-app | Deployment "pause-app" uses the default ServiceAccount, which may have unintended permissions. | CIS 5.1.5 · CIS 5.1.6 · MITRE T1078.001 · NSA 3.1 · NSA 3.2 |
| 🟠 High | privilege-escalation | kv-e2e-network/Deployment/pause-app (pause) | Container "pause" does not set allowPrivilegeEscalation to false, permitting privilege escalation. | CIS 5.2.6 · MITRE T1068 · MITRE T1611 · NSA 1.1 · NSA 2.1 |
| 🟠 High | run-as-root | kv-e2e-network/Deployment/pause-app (pause) | Container "pause" does not set runAsNonRoot: true and may run as root. | CIS 5.2.7 · MITRE T1611 · NSA 1.1 |
| 🟡 Medium | network-policy-overly-permissive | **2 resources** | NetworkPolicy "allow-all-egress" allows all egress traffic, providing no effective egress segmentation. | CIS 5.3.2 · MITRE T1046 · NSA 4.2 |
| 🟡 Medium | psa-labels-missing | kv-e2e-network/Namespace/kv-e2e-network | Namespace "kv-e2e-network" is missing the pod-security.kubernetes.io/enforce label; pod security is not enforced. | CIS 5.2.1 · MITRE T1610 · NSA 2.1 |
| 🟡 Medium | ingress-wildcard-host | **2 resources** | Ingress "no-class-ingress" has a rule with wildcard or empty host that matches all incoming requests. | CIS 5.3.2 · MITRE T1190 · NSA 4.1 |
| 🟡 Medium | service-type-nodeport | kv-e2e-network/Service/node-exposed | Service "node-exposed" is exposed as NodePort, which bypasses ingress controls and exposes ports on all cluster nodes. | CIS 5.3.2 · MITRE T1190 · NSA 4.1 |
| 🟡 Medium | apparmor-profile | kv-e2e-network/Deployment/pause-app (pause) | Container "pause" does not have an AppArmor profile set. | CIS 5.6.3 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | capabilities-not-dropped | kv-e2e-network/Deployment/pause-app (pause) | Container "pause" does not drop ALL capabilities, leaving it with unnecessary default privileges. | CIS 5.2.8 · CIS 5.2.10 · MITRE T1068 · NSA 1.1 |
| 🟡 Medium | image-pull-policy | kv-e2e-network/Deployment/pause-app (pause) | Container "pause" uses a mutable image tag with pullPolicy "IfNotPresent" (image: registry.k8s.io/pause:3.9), risking stale images. | CIS 5.5.1 · MITRE T1525 · NSA 1.4 |
| 🟡 Medium | psa-restricted-violations | **3 resources** | Deployment "pause-app" container "pause" violates PSS Restricted: runAsNonRoot is not true. | CIS 5.2.1 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | read-only-rootfs | kv-e2e-network/Deployment/pause-app (pause) | Container "pause" does not have a read-only root filesystem. | CIS 5.6.3 · MITRE T1565.001 · NSA 1.2 |
| 🟡 Medium | resource-limits-missing | kv-e2e-network/Deployment/pause-app (pause) | Container "pause" is missing both CPU and memory limits. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🟡 Medium | resource-requests-missing | kv-e2e-network/Deployment/pause-app (pause) | Container "pause" is missing both CPU and memory requests. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🟡 Medium | run-as-group | kv-e2e-network/Deployment/pause-app (pause) | Container "pause" does not set runAsGroup; the process will run as GID 0 (root group) by default. | CIS 5.2.7 · MITRE T1068 · NSA 1.1 |
| 🟡 Medium | seccomp-profile | kv-e2e-network/Deployment/pause-app (pause) | Container "pause" does not have a Seccomp profile set at either the container or pod level. | CIS 5.6.2 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | token-projection-config | kv-e2e-network/Deployment/pause-app | Deployment "pause-app" does not use explicitly configured projected ServiceAccount tokens with expiry and audience restrictions. | CIS 5.1.6 · MITRE T1552.007 · NSA 3.2 |
| 🟡 Medium | service-type-loadbalancer | kv-e2e-network/Service/public-lb | Service "public-lb" is exposed as LoadBalancer, which creates a cloud load balancer that may be publicly accessible. | CIS 5.3.2 · MITRE T1190 · NSA 4.1 |
| 🔵 Low | limit-range-missing | kv-e2e-network/Namespace/kv-e2e-network | Namespace "kv-e2e-network" has no LimitRange defined. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | resource-quota-missing | kv-e2e-network/Namespace/kv-e2e-network | Namespace "kv-e2e-network" has no ResourceQuota defined. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | ingress-class-missing | **3 resources** | Ingress "no-class-ingress" has no ingressClassName or ingress.class annotation. It may not be handled by any ingress controller. | CIS 5.3.2 · MITRE T1190 · NSA 4.1 |
| 🔵 Low | ephemeral-storage-limits | kv-e2e-network/Deployment/pause-app (pause) | Container "pause" is missing ephemeral-storage limits. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | image-no-digest | kv-e2e-network/Deployment/pause-app (pause) | Container "pause" image is not pinned by digest (image: registry.k8s.io/pause:3.9), allowing tag mutation. | CIS 5.5.1 · MITRE T1525 · NSA 1.4 |
| 🔵 Low | liveness-readiness-probes | **2 resources** | Container "pause" has no liveness probe configured. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | priority-class-missing | kv-e2e-network/Deployment/pause-app | Deployment "pause-app" has no PriorityClass set; it will be evicted first during resource pressure. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | runtime-class | kv-e2e-network/Deployment/pause-app | Pod "pause-app" does not specify a RuntimeClass, using the default (unsandboxed) runtime. | CIS 5.6.3 · MITRE T1611 · NSA 2.1 |
| 🔵 Low | topology-spread | kv-e2e-network/Deployment/pause-app | Deployment "pause-app" has no topology spread constraints; all replicas may be scheduled on the same node. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |

<details>
<summary>network-policy-default-deny: 2 affected resources</summary>

- `kv-e2e-network/Namespace/kv-e2e-network`
- `kv-e2e-network/Namespace/kv-e2e-network`

</details>

<details>
<summary>ingress-no-tls: 3 affected resources</summary>

- `kv-e2e-network/Ingress/no-class-ingress`
- `kv-e2e-network/Ingress/no-tls-ingress`
- `kv-e2e-network/Ingress/wildcard-host-ingress`

</details>

<details>
<summary>network-policy-overly-permissive: 2 affected resources</summary>

- `kv-e2e-network/NetworkPolicy/allow-all-egress`
- `kv-e2e-network/NetworkPolicy/allow-all-ingress`

</details>

<details>
<summary>ingress-wildcard-host: 2 affected resources</summary>

- `kv-e2e-network/Ingress/no-class-ingress`
- `kv-e2e-network/Ingress/wildcard-host-ingress`

</details>

<details>
<summary>psa-restricted-violations: 3 affected resources</summary>

- `kv-e2e-network/Deployment/pause-app (pause)`
- `kv-e2e-network/Deployment/pause-app (pause)`
- `kv-e2e-network/Deployment/pause-app (pause)`

</details>

<details>
<summary>ingress-class-missing: 3 affected resources</summary>

- `kv-e2e-network/Ingress/no-class-ingress`
- `kv-e2e-network/Ingress/no-tls-ingress`
- `kv-e2e-network/Ingress/wildcard-host-ingress`

</details>

<details>
<summary>liveness-readiness-probes: 2 affected resources</summary>

- `kv-e2e-network/Deployment/pause-app (pause)`
- `kv-e2e-network/Deployment/pause-app (pause)`

</details>

<details>
<summary>Remediation: external-ips (1 resources affected)</summary>

## Why This Matters

The `externalIPs` field allows a Service to claim arbitrary IP addresses, enabling CVE-2020-8554. An attacker with permission to create or update Services can redirect traffic destined for any external IP through their own pods, performing man-in-the-middle attacks on cluster traffic.

## How to Fix

Remove the `externalIPs` field and use a LoadBalancer or Ingress to expose the service externally:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: my-service
spec:
  type: LoadBalancer
  ports:
    - port: 443
      targetPort: 8443
  selector:
    app: my-app
  # externalIPs: []  # Remove this field entirely
```

Enable the `DenyServiceExternalIPs` admission controller to prevent externalIPs usage cluster-wide.

## Learn More

See CVE-2020-8554 for details on the externalIPs man-in-the-middle vulnerability. The Kubernetes documentation recommends using LoadBalancer or Ingress instead of externalIPs for production services.

**Affected resources:** kv-e2e-network/Service/hijack-svc

</details>

<details>
<summary>Remediation: network-policy-default-deny (2 resources affected)</summary>

## Why This Matters

Without a default-deny ingress policy, all inbound traffic to pods is allowed by default. An attacker who gains access to any pod in the cluster can reach services in this namespace, enabling lateral movement and data theft.

## How to Fix

Create a default-deny ingress NetworkPolicy that selects all pods, then add specific allow rules for legitimate traffic:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: my-namespace
spec:
  podSelector: {}
  policyTypes:
    - Ingress
```

Then create additional policies with explicit `ingress.from` rules for each service that needs to receive traffic.

## Learn More

Refer to the Kubernetes NetworkPolicy documentation and CIS Kubernetes Benchmark 5.3.2. Default-deny is a zero-trust network best practice recommended by the NSA/CISA Kubernetes Hardening Guide.

**Affected resources:** kv-e2e-network/Namespace/kv-e2e-network, kv-e2e-network/Namespace/kv-e2e-network

</details>

<details>
<summary>Remediation: ingress-no-tls (3 resources affected)</summary>

## Why This Matters

Without TLS, all traffic between clients and this Ingress is transmitted in plaintext over HTTP. Attackers on the network path can intercept credentials, session tokens, API keys, and other sensitive data through man-in-the-middle attacks.

## How to Fix

Add a `tls` section to the Ingress spec referencing a Secret that contains the TLS certificate and private key:

```yaml
spec:
  tls:
    - hosts:
        - app.example.com
      secretName: app-tls-cert
  rules:
    - host: app.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: app
                port:
                  number: 80
```

Use cert-manager to automate certificate provisioning and renewal via Let's Encrypt or your internal CA.

## Learn More

See the Kubernetes Ingress TLS documentation and CIS Kubernetes Benchmark 5.4.1. HTTPS should be enforced for all externally-facing endpoints to protect data in transit.

**Affected resources:** kv-e2e-network/Ingress/no-class-ingress, kv-e2e-network/Ingress/no-tls-ingress, kv-e2e-network/Ingress/wildcard-host-ingress

</details>

<details>
<summary>Remediation: automount-token (1 resources affected)</summary>

## Why This Matters

When a ServiceAccount token is auto-mounted, every container in the pod can call the Kubernetes API. If a container is compromised through a vulnerability or misconfiguration, the attacker gains API access to enumerate resources, read secrets, or escalate privileges.

## How to Fix

Disable auto-mounting at the pod spec level for workloads that do not need API access:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      automountServiceAccountToken: false
      containers:
        - name: app
          image: my-app:latest
```

For workloads that do require API access, use projected tokens with bounded lifetime and audience restrictions instead of the default long-lived token.

## Learn More

Refer to the Kubernetes documentation on configuring service accounts for pods and CIS Kubernetes Benchmark 5.1.6 for auto-mount token guidance.

**Affected resources:** kv-e2e-network/Deployment/pause-app

</details>

<details>
<summary>Remediation: default-service-account (1 resources affected)</summary>

## Why This Matters

The default ServiceAccount is shared by every pod in a namespace. If any pod is compromised, the attacker inherits whatever permissions have been granted to the default account via role bindings, enabling lateral movement across all workloads sharing it.

## How to Fix

Create a dedicated ServiceAccount for each workload and reference it in the pod spec:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-app
  namespace: production
automountServiceAccountToken: false
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      serviceAccountName: my-app
```

Grant only the permissions the workload actually needs via a dedicated Role and RoleBinding.

## Learn More

See the Kubernetes documentation on managing service accounts and CIS Kubernetes Benchmark 5.1.5 for guidance on ensuring default service accounts are not actively used.

**Affected resources:** kv-e2e-network/Deployment/pause-app

</details>

<details>
<summary>Remediation: privilege-escalation (1 resources affected)</summary>

## Why This Matters

By default, Kubernetes allows containers to escalate privileges via setuid/setgid binaries, which let a process gain more permissions than its parent. An attacker can exploit this using setuid binaries already present in the container image (like `su`, `sudo`, or `ping`) to elevate from a low-privilege user to root.

## How to Fix

Explicitly disable privilege escalation in the container's securityContext:

```yaml
securityContext:
  allowPrivilegeEscalation: false
  runAsNonRoot: true
  capabilities:
    drop: ["ALL"]
```

This blocks the use of setuid/setgid binaries and prevents the no_new_privs Linux flag from being cleared. The vast majority of application containers do not need privilege escalation.

## Learn More

This is required by the Pod Security Standards "Restricted" profile and CIS Benchmark 5.2.5. Disabling privilege escalation is one of the most impactful single-line security improvements you can make.

**Affected resources:** kv-e2e-network/Deployment/pause-app

</details>

<details>
<summary>Remediation: run-as-root (1 resources affected)</summary>

## Why This Matters

Without `runAsNonRoot: true`, Kubernetes does not enforce non-root execution and the container may default to running as UID 0 depending on the image's USER directive. If the image defaults to root, the container process gains full privileges, increasing the blast radius of any compromise or container escape.

## How to Fix

Enforce non-root execution in the securityContext:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
```

With `runAsNonRoot: true`, Kubernetes will reject the pod at admission time if the container image attempts to run as root. Setting an explicit `runAsUser` provides an additional guarantee.

## Learn More

This aligns with CIS Benchmark 5.2.6 and the Pod Security Standards "Restricted" profile. The `runAsNonRoot` field acts as a safety net even when images change their default USER.

**Affected resources:** kv-e2e-network/Deployment/pause-app

</details>

<details>
<summary>Remediation: network-policy-overly-permissive (2 resources affected)</summary>

## Why This Matters

This NetworkPolicy allows egress traffic to any destination, which is equivalent to having no egress restriction at all. A compromised pod can exfiltrate data to external servers, reach cloud metadata endpoints, or communicate with command-and-control infrastructure.

## How to Fix

Replace the permissive rule with specific destination selectors that limit traffic to known, required endpoints:

```yaml
spec:
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: database
      ports:
        - port: 5432
          protocol: TCP
    - to:
        - namespaceSelector: {}
      ports:
        - port: 53
          protocol: UDP
```

Always include a DNS egress rule (port 53) so pods can resolve service names.

## Learn More

Refer to the Kubernetes NetworkPolicy documentation on egress rules. The NSA/CISA Kubernetes Hardening Guide recommends restricting egress to prevent data exfiltration.

**Affected resources:** kv-e2e-network/NetworkPolicy/allow-all-egress, kv-e2e-network/NetworkPolicy/allow-all-ingress

</details>

<details>
<summary>Remediation: psa-labels-missing (1 resources affected)</summary>

## Why This Matters

Without PSA enforcement labels, any pod configuration is allowed in this namespace, including privileged containers, host namespace access, and root execution. This bypasses Kubernetes' built-in Pod Security Standards and leaves the namespace vulnerable to workloads that could compromise the node.

## How to Fix

Add Pod Security Admission labels to enforce a security profile on all pods in the namespace:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: kv-e2e-network
  labels:
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

Start with `baseline` enforcement to block known privilege escalations, then upgrade to `restricted` after verifying all workloads are compliant.

## Learn More

See the Kubernetes Pod Security Admission documentation and CIS Kubernetes Benchmark 5.2. The three-tier approach (enforce, audit, warn) allows gradual adoption of stricter profiles.

**Affected resources:** kv-e2e-network/Namespace/kv-e2e-network

</details>

<details>
<summary>Remediation: ingress-wildcard-host (2 resources affected)</summary>

## Why This Matters

A wildcard or empty host in an Ingress rule matches all incoming requests regardless of the Host header. This can expose backend services to unintended traffic, enable host header injection attacks, and make it difficult to enforce per-domain security policies like TLS and authentication.

## How to Fix

Replace the wildcard or empty host with an explicit, fully-qualified domain name:

```yaml
spec:
  rules:
    - host: app.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: app
                port:
                  number: 80
```

If multiple domains are needed, create separate rules with explicit hosts for each.

## Learn More

Refer to the Kubernetes Ingress documentation on host-based routing. Explicit host matching is a security best practice that prevents unintended routing and simplifies audit trails.

**Affected resources:** kv-e2e-network/Ingress/no-class-ingress, kv-e2e-network/Ingress/wildcard-host-ingress

</details>

<details>
<summary>Remediation: service-type-nodeport (1 resources affected)</summary>

## Why This Matters

NodePort services open a port (30000-32767) on every node in the cluster, bypassing Ingress controllers and their centralized security controls. Any network client that can reach a cluster node's IP address can access the service, significantly widening the attack surface.

## How to Fix

Replace the NodePort service with a ClusterIP service and expose it through an Ingress controller:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: my-service
spec:
  type: ClusterIP
  ports:
    - port: 80
      targetPort: 8080
  selector:
    app: my-app
```

Ingress controllers centralize TLS termination, authentication, rate limiting, and access logging in a single entry point.

## Learn More

See the Kubernetes Service documentation and CIS Kubernetes Benchmark 5.4. If NodePort is unavoidable, restrict access using firewall rules to limit which source IPs can reach the node ports.

**Affected resources:** kv-e2e-network/Service/node-exposed

</details>

<details>
<summary>Remediation: apparmor-profile (1 resources affected)</summary>

## Why This Matters

AppArmor provides mandatory access control (MAC) that restricts which files, network resources, and capabilities a container process can access. Without an AppArmor profile, the container operates without these restrictions, allowing an attacker with code execution to access any file the container user can read and make unrestricted network connections.

## How to Fix

Apply an AppArmor profile in the container's securityContext (Kubernetes 1.30+):

```yaml
securityContext:
  appArmorProfile:
    type: RuntimeDefault
```

The RuntimeDefault profile provides sensible restrictions for most applications. For tighter control, create a custom Localhost profile that only allows the specific file and network access your application needs.

## Learn More

AppArmor is available on Debian/Ubuntu-based nodes. RHEL/CentOS nodes use SELinux instead. Both provide MAC enforcement. Refer to CIS Benchmark 5.7.5 and the Kubernetes AppArmor documentation.

**Affected resources:** kv-e2e-network/Deployment/pause-app

</details>

<details>
<summary>Remediation: capabilities-not-dropped (1 resources affected)</summary>

## Why This Matters

By default, containers receive a set of Linux capabilities including KILL, SETUID, SETGID, and NET_RAW. These defaults are rarely needed by application code and significantly increase the potential damage from a container compromise. Dropping all capabilities follows the principle of least privilege.

## How to Fix

Explicitly drop all capabilities and selectively add back only what your application needs:

```yaml
securityContext:
  capabilities:
    drop: ["ALL"]
    add: ["NET_BIND_SERVICE"]  # Only if needed
```

Most web applications, API servers, and background workers run perfectly with all capabilities dropped. Test your application after making this change to confirm no functionality is lost.

## Learn More

This is required by the Pod Security Standards "Restricted" profile and aligns with CIS Benchmark 5.2.7. Kubernetes best practice is to treat capability grants as exceptions that require explicit justification.

**Affected resources:** kv-e2e-network/Deployment/pause-app

</details>

<details>
<summary>Remediation: image-pull-policy (1 resources affected)</summary>

## Why This Matters

When a mutable image tag is used without `imagePullPolicy: Always`, Kubernetes may serve a cached version of the image from the node. If the tag has been updated in the registry (with a security patch or -- worse -- a compromised layer), the running container will not reflect those changes.

## How to Fix

Set `imagePullPolicy: Always` for any container using a mutable tag:

```yaml
containers:
  - name: app
    image: nginx:1.25.3
    imagePullPolicy: Always   # Forces fresh pull each time
```

Alternatively, pin images by digest (`image@sha256:...`), which makes the pull policy irrelevant because the content is immutable.

## Learn More

See the Kubernetes documentation on image pull policies and CIS Kubernetes Benchmark 5.4.2 for pull policy guidance.

**Affected resources:** kv-e2e-network/Deployment/pause-app

</details>

<details>
<summary>Remediation: psa-restricted-violations (3 resources affected)</summary>

## Why This Matters

Running as root inside a container means that any container escape vulnerability immediately grants root access on the host node. Even without an escape, root inside the container can modify sensitive files, install packages, and access capabilities that non-root users cannot.

## How to Fix

Set `runAsNonRoot: true` and specify a non-root user ID in the security context:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
```

Set this at the pod level to apply to all containers. Ensure your container image supports running as a non-root user (many official images do).

## Learn More

See the Pod Security Standards Restricted profile and CIS Kubernetes Benchmark 5.2.6. Running as non-root is a fundamental container security best practice.

**Affected resources:** kv-e2e-network/Deployment/pause-app, kv-e2e-network/Deployment/pause-app, kv-e2e-network/Deployment/pause-app

</details>

<details>
<summary>Remediation: read-only-rootfs (1 resources affected)</summary>

## Why This Matters

A writable root filesystem allows an attacker who gains code execution in your container to modify application binaries, install attack tools, plant backdoors, or persist malware across container restarts. Making the filesystem read-only eliminates an entire class of post-exploitation techniques.

## How to Fix

Enable a read-only root filesystem and mount writable volumes only where needed:

```yaml
securityContext:
  readOnlyRootFilesystem: true
volumeMounts:
  - name: tmp
    mountPath: /tmp
volumes:
  - name: tmp
    emptyDir: {}
```

Common paths that need write access include /tmp, /var/cache, and /var/run. Mount each as an emptyDir or tmpfs volume rather than making the entire filesystem writable.

## Learn More

This aligns with CIS Benchmark 5.2.4 and the defense-in-depth principle. Combined with dropping capabilities and running as non-root, a read-only filesystem forms a strong container hardening baseline.

**Affected resources:** kv-e2e-network/Deployment/pause-app

</details>

<details>
<summary>Remediation: resource-limits-missing (1 resources affected)</summary>

## Why This Matters

Without resource limits, a single container can consume all available CPU and memory on a node, starving other workloads and triggering cascading failures. An attacker who compromises an unlimited container can mount a denial-of-service attack against the entire node with a simple fork bomb or memory allocation loop.

## How to Fix

Set both CPU and memory limits based on your application's actual resource usage:

```yaml
resources:
  limits:
    cpu: 500m
    memory: 256Mi
  requests:
    cpu: 100m
    memory: 128Mi
```

Profile your application under load to determine appropriate values. Set limits to handle peak usage and requests to match steady-state consumption.

## Learn More

Use LimitRange objects to enforce default limits at the namespace level. Resource limits also determine the pod's QoS class: pods with equal requests and limits get Guaranteed QoS and are last to be evicted.

**Affected resources:** kv-e2e-network/Deployment/pause-app

</details>

<details>
<summary>Remediation: resource-requests-missing (1 resources affected)</summary>

## Why This Matters

Resource requests tell the Kubernetes scheduler how much CPU and memory your container needs. Without requests, the scheduler treats the pod as needing zero resources and may pack too many pods onto a single node. This leads to overcommitment, resource contention, throttling, and OOM kills under load.

## How to Fix

Set resource requests based on your application's steady-state usage:

```yaml
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 256Mi
```

Observe your application's actual resource consumption using `kubectl top` or a monitoring tool, then set requests to match the typical steady-state usage.

## Learn More

Resource requests determine the pod's QoS class and scheduling behavior. Pods with requests equal to limits receive Guaranteed QoS. Use Vertical Pod Autoscaler (VPA) to automatically recommend request values.

**Affected resources:** kv-e2e-network/Deployment/pause-app

</details>

<details>
<summary>Remediation: run-as-group (1 resources affected)</summary>

## Why This Matters

Without an explicit runAsGroup, the container process defaults to GID 0 (the root group). Files and sockets owned by the root group become accessible to the container, including potentially sensitive host files if volumes are mounted. This widens the attack surface unnecessarily.

## How to Fix

Set an explicit non-root group in the securityContext:

```yaml
securityContext:
  runAsGroup: 1000
  runAsUser: 1000
  runAsNonRoot: true
```

Ensure the container image's application files and directories are readable by the specified GID. You may need to adjust file ownership in your Dockerfile with `chown`.

## Learn More

This aligns with CIS Benchmark 5.2.6 and the Pod Security Standards "Restricted" profile. Always set runAsUser, runAsGroup, and runAsNonRoot together for comprehensive identity control.

**Affected resources:** kv-e2e-network/Deployment/pause-app

</details>

<details>
<summary>Remediation: seccomp-profile (1 resources affected)</summary>

## Why This Matters

Without a Seccomp profile, containers can invoke any of the 300+ Linux system calls, leaving the entire kernel attack surface exposed. Kernel vulnerabilities in obscure syscalls are a primary vector for container escapes. Seccomp filtering blocks dangerous syscalls that legitimate applications never use.

## How to Fix

Apply a Seccomp profile at the container or pod level:

```yaml
securityContext:
  seccompProfile:
    type: RuntimeDefault
```

The RuntimeDefault profile blocks approximately 50 dangerous syscalls while allowing normal application behavior. For stricter controls, use a custom Localhost profile tailored to your application's needs. Set the profile at the pod level to apply it to all containers.

## Learn More

Seccomp profiles are required by the Pod Security Standards "Restricted" profile and CIS Benchmark 5.7.2. Use tools like `strace` or the Security Profiles Operator to generate custom profiles for your workloads.

**Affected resources:** kv-e2e-network/Deployment/pause-app

</details>

<details>
<summary>Remediation: token-projection-config (1 resources affected)</summary>

## Why This Matters

Without explicit projection configuration, ServiceAccount tokens use Kubernetes defaults: no audience restriction and a long expiration. A stolen token remains valid for an extended period and can be used against any API server endpoint, widening the blast radius of a compromise.

## How to Fix

Add a projected volume with explicit expiration and audience:

```yaml
spec:
  volumes:
    - name: token
      projected:
        sources:
          - serviceAccountToken:
              expirationSeconds: 3600
              audience: my-api
              path: token
  containers:
    - name: app
      volumeMounts:
        - name: token
          mountPath: /var/run/secrets/tokens
          readOnly: true
```

Projected tokens auto-rotate before expiry and are rejected by endpoints outside the specified audience.

## Learn More

See the Kubernetes documentation on projected volumes and service account token volume projection for detailed configuration options.

**Affected resources:** kv-e2e-network/Deployment/pause-app

</details>

<details>
<summary>Remediation: service-type-loadbalancer (1 resources affected)</summary>

## Why This Matters

LoadBalancer services provision cloud load balancers that are often publicly accessible by default. This exposes the service directly to the internet without centralized security controls such as TLS termination, authentication, WAF rules, and rate limiting that an Ingress controller provides.

## How to Fix

Replace the LoadBalancer service with a ClusterIP service and route traffic through an Ingress controller:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: my-service
spec:
  type: ClusterIP
  ports:
    - port: 80
      targetPort: 8080
  selector:
    app: my-app
```

If a LoadBalancer is required, use cloud-specific annotations to restrict access (e.g., `service.beta.kubernetes.io/aws-load-balancer-internal: "true"`) and configure security groups.

## Learn More

See the Kubernetes Service documentation and CIS Kubernetes Benchmark 5.4. Minimize the use of LoadBalancer services and prefer Ingress controllers for centralized traffic management.

**Affected resources:** kv-e2e-network/Service/public-lb

</details>

<details>
<summary>Remediation: limit-range-missing (1 resources affected)</summary>

## Why This Matters

Without a LimitRange, any container can be created without resource constraints. A single runaway or malicious pod can consume all node CPU and memory, causing denial of service for other workloads on the same node.

## How to Fix

Create a LimitRange in the namespace to set default and maximum resource constraints:

```yaml
apiVersion: v1
kind: LimitRange
metadata:
  name: default-limits
  namespace: my-app
spec:
  limits:
    - type: Container
      default:
        cpu: 500m
        memory: 256Mi
      defaultRequest:
        cpu: 100m
        memory: 128Mi
      max:
        cpu: "2"
        memory: 1Gi
```

Containers that omit resource requests/limits will inherit these defaults automatically.

## Learn More

CIS Kubernetes Benchmark 5.2.1 recommends LimitRanges for resource governance. See https://kubernetes.io/docs/concepts/policy/limit-range/ for configuration details.

**Affected resources:** kv-e2e-network/Namespace/kv-e2e-network

</details>

<details>
<summary>Remediation: resource-quota-missing (1 resources affected)</summary>

## Why This Matters

Without a ResourceQuota, a single namespace can consume the entire cluster's CPU, memory, and storage. This creates a noisy-neighbor problem where one team's workloads starve others, and makes capacity planning impossible.

## How to Fix

Create a ResourceQuota to cap the namespace's total resource consumption:

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: compute-quota
  namespace: my-app
spec:
  hard:
    requests.cpu: "10"
    requests.memory: 20Gi
    limits.cpu: "20"
    limits.memory: 40Gi
    pods: "50"
    services: "10"
```

Tune quota values based on the namespace's actual workload requirements and cluster capacity.

## Learn More

CIS Kubernetes Benchmark 5.2.2 recommends ResourceQuotas for multi-tenant clusters. See https://kubernetes.io/docs/concepts/policy/resource-quotas/ for quota configuration and enforcement behavior.

**Affected resources:** kv-e2e-network/Namespace/kv-e2e-network

</details>

<details>
<summary>Remediation: ingress-class-missing (3 resources affected)</summary>

## Why This Matters

Without an explicit IngressClass, this Ingress relies on the cluster's default ingress controller. If no default is configured, the Ingress may be silently ignored. If multiple controllers exist, the wrong one may claim it, leading to misrouted traffic or missing security configurations like WAF rules and rate limiting.

## How to Fix

Set the `ingressClassName` field to explicitly declare which controller should handle this Ingress:

```yaml
spec:
  ingressClassName: nginx
  rules:
    - host: app.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: app
                port:
                  number: 80
```

List available IngressClasses with `kubectl get ingressclass` to find the correct class name.

## Learn More

Refer to the Kubernetes IngressClass documentation. The deprecated `kubernetes.io/ingress.class` annotation is still supported but `spec.ingressClassName` is the preferred approach in Kubernetes 1.18+.

**Affected resources:** kv-e2e-network/Ingress/no-class-ingress, kv-e2e-network/Ingress/no-tls-ingress, kv-e2e-network/Ingress/wildcard-host-ingress

</details>

<details>
<summary>Remediation: ephemeral-storage-limits (1 resources affected)</summary>

## Why This Matters

Ephemeral storage includes container logs, emptyDir volumes, and the writable container layer. Without limits, a single container can fill the node's root disk, triggering eviction of all pods on that node and potentially causing a cascading failure across your cluster. This is a common denial-of-service vector.

## How to Fix

Set ephemeral-storage limits alongside your CPU and memory limits:

```yaml
resources:
  limits:
    ephemeral-storage: 1Gi
  requests:
    ephemeral-storage: 500Mi
```

Estimate your application's disk usage from logs, temporary files, and cache data. If your application writes large temporary files, consider using a PersistentVolumeClaim instead of ephemeral storage.

## Learn More

The kubelet evicts pods that exceed their ephemeral-storage limit. Use LimitRange to set default ephemeral-storage limits at the namespace level to catch containers that omit this setting.

**Affected resources:** kv-e2e-network/Deployment/pause-app

</details>

<details>
<summary>Remediation: image-no-digest (1 resources affected)</summary>

## Why This Matters

Image tags are mutable pointers -- a registry administrator or attacker can re-push a different image under the same tag. Without a digest, you have no cryptographic guarantee that the image you deploy is the one you tested.

## How to Fix

Pin images by their SHA-256 content digest for a fully immutable reference:

```yaml
containers:
  - name: app
    image: nginx@sha256:a8281ce420348a01ea6e   # Immutable
```

Use `crane digest nginx:1.25.3` or `skopeo inspect` to resolve a tag to its digest during CI/CD, then commit the pinned reference.

## Learn More

SLSA Level 1+ and NIST SP 800-190 recommend digest pinning for container supply chain integrity. See the Kubernetes images documentation for details.

**Affected resources:** kv-e2e-network/Deployment/pause-app

</details>

<details>
<summary>Remediation: liveness-readiness-probes (2 resources affected)</summary>

## Why This Matters

Without a liveness probe, Kubernetes cannot detect when a container has become unresponsive or deadlocked. The container continues running and consuming resources while failing to serve traffic. Users experience timeouts and errors until someone manually intervenes.

## How to Fix

Add a liveness probe that checks the container's health:

```yaml
containers:
  - name: app
    livenessProbe:
      httpGet:
        path: /healthz
        port: 8080
      initialDelaySeconds: 15
      periodSeconds: 10
      failureThreshold: 3
```

Use `httpGet` for HTTP services, `tcpSocket` for TCP services, or `exec` with a custom health check script for non-network workloads.

## Learn More

See the Kubernetes documentation on container probes. Set initialDelaySeconds high enough for your application to start, and consider adding a startupProbe for slow-starting containers.

**Affected resources:** kv-e2e-network/Deployment/pause-app, kv-e2e-network/Deployment/pause-app

</details>

<details>
<summary>Remediation: priority-class-missing (1 resources affected)</summary>

## Why This Matters

Without a PriorityClass, pods receive default priority (typically 0) and are among the first to be evicted during resource pressure or node maintenance. This means important application workloads may be killed before less critical ones, leading to unpredictable outages.

## How to Fix

Define PriorityClasses for your workloads and assign them appropriately:

```yaml
apiVersion: scheduling.k8s.io/v1
kind: PriorityClass
metadata:
  name: app-medium
value: 100000
---
# Reference in your workload:
spec:
  priorityClassName: app-medium
```

Create a tiered priority scheme (e.g., app-critical: 500000, app-medium: 100000, app-low: 10000) that reflects your workload importance hierarchy.

## Learn More

Refer to the Kubernetes Pod Priority and Preemption documentation. Establishing a consistent priority scheme across namespaces ensures predictable eviction behavior during resource contention.

**Affected resources:** kv-e2e-network/Deployment/pause-app

</details>

<details>
<summary>Remediation: runtime-class (1 resources affected)</summary>

## Why This Matters

Without a RuntimeClass, pods use the default container runtime (typically runc), which shares the host kernel directly with containers. A kernel vulnerability can allow container escape to the host. Sandboxed runtimes like gVisor or Kata Containers add an additional isolation layer that intercepts system calls or runs containers in lightweight VMs.

## How to Fix

Specify a sandboxed RuntimeClass in the pod spec:

```yaml
spec:
  runtimeClassName: gvisor
```

Available RuntimeClasses depend on your cluster configuration. Common options include `gvisor` (user-space kernel), `kata` (micro-VMs), and `firecracker`. Check your cluster's available RuntimeClasses with `kubectl get runtimeclasses`.

## Learn More

Sandboxed runtimes are especially important for multi-tenant clusters and workloads processing untrusted input. They add latency overhead, so evaluate performance requirements. See the Kubernetes RuntimeClass documentation.

**Affected resources:** kv-e2e-network/Deployment/pause-app

</details>

<details>
<summary>Remediation: topology-spread (1 resources affected)</summary>

## Why This Matters

Without topology spread constraints, the scheduler may place all replicas on the same node or in the same availability zone. If that node or zone fails, your entire service goes down despite having multiple replicas. This negates the high-availability benefits of running multiple pods.

## How to Fix

Add topology spread constraints to distribute replicas across failure domains:

```yaml
spec:
  topologySpreadConstraints:
    - maxSkew: 1
      topologyKey: kubernetes.io/hostname
      whenUnsatisfiable: DoNotSchedule
      labelSelector:
        matchLabels:
          app: my-app
    - maxSkew: 1
      topologyKey: topology.kubernetes.io/zone
      whenUnsatisfiable: ScheduleAnyway
```

Use `kubernetes.io/hostname` for node-level spreading and `topology.kubernetes.io/zone` for zone-level spreading.

## Learn More

See the Kubernetes Pod Topology Spread Constraints documentation. Combining hostname and zone constraints provides both node-level and zone-level fault tolerance.

**Affected resources:** kv-e2e-network/Deployment/pause-app

</details>

### kv-e2e-network-deny (28 findings — 🟠6 🟡13 🔵9)

| Severity | Check | Resources | Message | Frameworks |
|----------|-------|-----------|---------|-----------|
| 🟠 High | network-policy-default-deny | **2 resources** | Namespace "kv-e2e-network-deny" is missing a default-deny ingress NetworkPolicy. | CIS 5.3.2 · MITRE T1046 · MITRE T1071 · NSA 4.2 |
| 🟠 High | automount-token | kv-e2e-network-deny/Deployment/web | Deployment "web" auto-mounts a ServiceAccount token. Most workloads do not need Kubernetes API access. | CIS 5.1.6 · MITRE T1552.007 · NSA 3.2 |
| 🟠 High | default-service-account | kv-e2e-network-deny/Deployment/web | Deployment "web" uses the default ServiceAccount, which may have unintended permissions. | CIS 5.1.5 · CIS 5.1.6 · MITRE T1078.001 · NSA 3.1 · NSA 3.2 |
| 🟠 High | privilege-escalation | kv-e2e-network-deny/Deployment/web (pause) | Container "pause" does not set allowPrivilegeEscalation to false, permitting privilege escalation. | CIS 5.2.6 · MITRE T1068 · MITRE T1611 · NSA 1.1 · NSA 2.1 |
| 🟠 High | run-as-root | kv-e2e-network-deny/Deployment/web (pause) | Container "pause" does not set runAsNonRoot: true and may run as root. | CIS 5.2.7 · MITRE T1611 · NSA 1.1 |
| 🟡 Medium | psa-labels-missing | kv-e2e-network-deny/Namespace/kv-e2e-network-deny | Namespace "kv-e2e-network-deny" is missing the pod-security.kubernetes.io/enforce label; pod security is not enforced. | CIS 5.2.1 · MITRE T1610 · NSA 2.1 |
| 🟡 Medium | apparmor-profile | kv-e2e-network-deny/Deployment/web (pause) | Container "pause" does not have an AppArmor profile set. | CIS 5.6.3 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | capabilities-not-dropped | kv-e2e-network-deny/Deployment/web (pause) | Container "pause" does not drop ALL capabilities, leaving it with unnecessary default privileges. | CIS 5.2.8 · CIS 5.2.10 · MITRE T1068 · NSA 1.1 |
| 🟡 Medium | image-pull-policy | kv-e2e-network-deny/Deployment/web (pause) | Container "pause" uses a mutable image tag with pullPolicy "IfNotPresent" (image: registry.k8s.io/pause:3.9), risking stale images. | CIS 5.5.1 · MITRE T1525 · NSA 1.4 |
| 🟡 Medium | psa-restricted-violations | **3 resources** | Deployment "web" container "pause" violates PSS Restricted: runAsNonRoot is not true. | CIS 5.2.1 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | read-only-rootfs | kv-e2e-network-deny/Deployment/web (pause) | Container "pause" does not have a read-only root filesystem. | CIS 5.6.3 · MITRE T1565.001 · NSA 1.2 |
| 🟡 Medium | resource-limits-missing | kv-e2e-network-deny/Deployment/web (pause) | Container "pause" is missing both CPU and memory limits. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🟡 Medium | resource-requests-missing | kv-e2e-network-deny/Deployment/web (pause) | Container "pause" is missing both CPU and memory requests. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🟡 Medium | run-as-group | kv-e2e-network-deny/Deployment/web (pause) | Container "pause" does not set runAsGroup; the process will run as GID 0 (root group) by default. | CIS 5.2.7 · MITRE T1068 · NSA 1.1 |
| 🟡 Medium | seccomp-profile | kv-e2e-network-deny/Deployment/web (pause) | Container "pause" does not have a Seccomp profile set at either the container or pod level. | CIS 5.6.2 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | token-projection-config | kv-e2e-network-deny/Deployment/web | Deployment "web" does not use explicitly configured projected ServiceAccount tokens with expiry and audience restrictions. | CIS 5.1.6 · MITRE T1552.007 · NSA 3.2 |
| 🔵 Low | limit-range-missing | kv-e2e-network-deny/Namespace/kv-e2e-network-deny | Namespace "kv-e2e-network-deny" has no LimitRange defined. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | resource-quota-missing | kv-e2e-network-deny/Namespace/kv-e2e-network-deny | Namespace "kv-e2e-network-deny" has no ResourceQuota defined. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | ephemeral-storage-limits | kv-e2e-network-deny/Deployment/web (pause) | Container "pause" is missing ephemeral-storage limits. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | image-no-digest | kv-e2e-network-deny/Deployment/web (pause) | Container "pause" image is not pinned by digest (image: registry.k8s.io/pause:3.9), allowing tag mutation. | CIS 5.5.1 · MITRE T1525 · NSA 1.4 |
| 🔵 Low | liveness-readiness-probes | **2 resources** | Container "pause" has no liveness probe configured. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | priority-class-missing | kv-e2e-network-deny/Deployment/web | Deployment "web" has no PriorityClass set; it will be evicted first during resource pressure. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | runtime-class | kv-e2e-network-deny/Deployment/web | Pod "web" does not specify a RuntimeClass, using the default (unsandboxed) runtime. | CIS 5.6.3 · MITRE T1611 · NSA 2.1 |
| 🔵 Low | topology-spread | kv-e2e-network-deny/Deployment/web | Deployment "web" has no topology spread constraints; all replicas may be scheduled on the same node. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |

<details>
<summary>network-policy-default-deny: 2 affected resources</summary>

- `kv-e2e-network-deny/Namespace/kv-e2e-network-deny`
- `kv-e2e-network-deny/Namespace/kv-e2e-network-deny`

</details>

<details>
<summary>psa-restricted-violations: 3 affected resources</summary>

- `kv-e2e-network-deny/Deployment/web (pause)`
- `kv-e2e-network-deny/Deployment/web (pause)`
- `kv-e2e-network-deny/Deployment/web (pause)`

</details>

<details>
<summary>liveness-readiness-probes: 2 affected resources</summary>

- `kv-e2e-network-deny/Deployment/web (pause)`
- `kv-e2e-network-deny/Deployment/web (pause)`

</details>

<details>
<summary>Remediation: network-policy-default-deny (2 resources affected)</summary>

## Why This Matters

Without a default-deny ingress policy, all inbound traffic to pods is allowed by default. An attacker who gains access to any pod in the cluster can reach services in this namespace, enabling lateral movement and data theft.

## How to Fix

Create a default-deny ingress NetworkPolicy that selects all pods, then add specific allow rules for legitimate traffic:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: my-namespace
spec:
  podSelector: {}
  policyTypes:
    - Ingress
```

Then create additional policies with explicit `ingress.from` rules for each service that needs to receive traffic.

## Learn More

Refer to the Kubernetes NetworkPolicy documentation and CIS Kubernetes Benchmark 5.3.2. Default-deny is a zero-trust network best practice recommended by the NSA/CISA Kubernetes Hardening Guide.

**Affected resources:** kv-e2e-network-deny/Namespace/kv-e2e-network-deny, kv-e2e-network-deny/Namespace/kv-e2e-network-deny

</details>

<details>
<summary>Remediation: automount-token (1 resources affected)</summary>

## Why This Matters

When a ServiceAccount token is auto-mounted, every container in the pod can call the Kubernetes API. If a container is compromised through a vulnerability or misconfiguration, the attacker gains API access to enumerate resources, read secrets, or escalate privileges.

## How to Fix

Disable auto-mounting at the pod spec level for workloads that do not need API access:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      automountServiceAccountToken: false
      containers:
        - name: app
          image: my-app:latest
```

For workloads that do require API access, use projected tokens with bounded lifetime and audience restrictions instead of the default long-lived token.

## Learn More

Refer to the Kubernetes documentation on configuring service accounts for pods and CIS Kubernetes Benchmark 5.1.6 for auto-mount token guidance.

**Affected resources:** kv-e2e-network-deny/Deployment/web

</details>

<details>
<summary>Remediation: default-service-account (1 resources affected)</summary>

## Why This Matters

The default ServiceAccount is shared by every pod in a namespace. If any pod is compromised, the attacker inherits whatever permissions have been granted to the default account via role bindings, enabling lateral movement across all workloads sharing it.

## How to Fix

Create a dedicated ServiceAccount for each workload and reference it in the pod spec:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-app
  namespace: production
automountServiceAccountToken: false
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      serviceAccountName: my-app
```

Grant only the permissions the workload actually needs via a dedicated Role and RoleBinding.

## Learn More

See the Kubernetes documentation on managing service accounts and CIS Kubernetes Benchmark 5.1.5 for guidance on ensuring default service accounts are not actively used.

**Affected resources:** kv-e2e-network-deny/Deployment/web

</details>

<details>
<summary>Remediation: privilege-escalation (1 resources affected)</summary>

## Why This Matters

By default, Kubernetes allows containers to escalate privileges via setuid/setgid binaries, which let a process gain more permissions than its parent. An attacker can exploit this using setuid binaries already present in the container image (like `su`, `sudo`, or `ping`) to elevate from a low-privilege user to root.

## How to Fix

Explicitly disable privilege escalation in the container's securityContext:

```yaml
securityContext:
  allowPrivilegeEscalation: false
  runAsNonRoot: true
  capabilities:
    drop: ["ALL"]
```

This blocks the use of setuid/setgid binaries and prevents the no_new_privs Linux flag from being cleared. The vast majority of application containers do not need privilege escalation.

## Learn More

This is required by the Pod Security Standards "Restricted" profile and CIS Benchmark 5.2.5. Disabling privilege escalation is one of the most impactful single-line security improvements you can make.

**Affected resources:** kv-e2e-network-deny/Deployment/web

</details>

<details>
<summary>Remediation: run-as-root (1 resources affected)</summary>

## Why This Matters

Without `runAsNonRoot: true`, Kubernetes does not enforce non-root execution and the container may default to running as UID 0 depending on the image's USER directive. If the image defaults to root, the container process gains full privileges, increasing the blast radius of any compromise or container escape.

## How to Fix

Enforce non-root execution in the securityContext:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
```

With `runAsNonRoot: true`, Kubernetes will reject the pod at admission time if the container image attempts to run as root. Setting an explicit `runAsUser` provides an additional guarantee.

## Learn More

This aligns with CIS Benchmark 5.2.6 and the Pod Security Standards "Restricted" profile. The `runAsNonRoot` field acts as a safety net even when images change their default USER.

**Affected resources:** kv-e2e-network-deny/Deployment/web

</details>

<details>
<summary>Remediation: psa-labels-missing (1 resources affected)</summary>

## Why This Matters

Without PSA enforcement labels, any pod configuration is allowed in this namespace, including privileged containers, host namespace access, and root execution. This bypasses Kubernetes' built-in Pod Security Standards and leaves the namespace vulnerable to workloads that could compromise the node.

## How to Fix

Add Pod Security Admission labels to enforce a security profile on all pods in the namespace:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: kv-e2e-network-deny
  labels:
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

Start with `baseline` enforcement to block known privilege escalations, then upgrade to `restricted` after verifying all workloads are compliant.

## Learn More

See the Kubernetes Pod Security Admission documentation and CIS Kubernetes Benchmark 5.2. The three-tier approach (enforce, audit, warn) allows gradual adoption of stricter profiles.

**Affected resources:** kv-e2e-network-deny/Namespace/kv-e2e-network-deny

</details>

<details>
<summary>Remediation: apparmor-profile (1 resources affected)</summary>

## Why This Matters

AppArmor provides mandatory access control (MAC) that restricts which files, network resources, and capabilities a container process can access. Without an AppArmor profile, the container operates without these restrictions, allowing an attacker with code execution to access any file the container user can read and make unrestricted network connections.

## How to Fix

Apply an AppArmor profile in the container's securityContext (Kubernetes 1.30+):

```yaml
securityContext:
  appArmorProfile:
    type: RuntimeDefault
```

The RuntimeDefault profile provides sensible restrictions for most applications. For tighter control, create a custom Localhost profile that only allows the specific file and network access your application needs.

## Learn More

AppArmor is available on Debian/Ubuntu-based nodes. RHEL/CentOS nodes use SELinux instead. Both provide MAC enforcement. Refer to CIS Benchmark 5.7.5 and the Kubernetes AppArmor documentation.

**Affected resources:** kv-e2e-network-deny/Deployment/web

</details>

<details>
<summary>Remediation: capabilities-not-dropped (1 resources affected)</summary>

## Why This Matters

By default, containers receive a set of Linux capabilities including KILL, SETUID, SETGID, and NET_RAW. These defaults are rarely needed by application code and significantly increase the potential damage from a container compromise. Dropping all capabilities follows the principle of least privilege.

## How to Fix

Explicitly drop all capabilities and selectively add back only what your application needs:

```yaml
securityContext:
  capabilities:
    drop: ["ALL"]
    add: ["NET_BIND_SERVICE"]  # Only if needed
```

Most web applications, API servers, and background workers run perfectly with all capabilities dropped. Test your application after making this change to confirm no functionality is lost.

## Learn More

This is required by the Pod Security Standards "Restricted" profile and aligns with CIS Benchmark 5.2.7. Kubernetes best practice is to treat capability grants as exceptions that require explicit justification.

**Affected resources:** kv-e2e-network-deny/Deployment/web

</details>

<details>
<summary>Remediation: image-pull-policy (1 resources affected)</summary>

## Why This Matters

When a mutable image tag is used without `imagePullPolicy: Always`, Kubernetes may serve a cached version of the image from the node. If the tag has been updated in the registry (with a security patch or -- worse -- a compromised layer), the running container will not reflect those changes.

## How to Fix

Set `imagePullPolicy: Always` for any container using a mutable tag:

```yaml
containers:
  - name: app
    image: nginx:1.25.3
    imagePullPolicy: Always   # Forces fresh pull each time
```

Alternatively, pin images by digest (`image@sha256:...`), which makes the pull policy irrelevant because the content is immutable.

## Learn More

See the Kubernetes documentation on image pull policies and CIS Kubernetes Benchmark 5.4.2 for pull policy guidance.

**Affected resources:** kv-e2e-network-deny/Deployment/web

</details>

<details>
<summary>Remediation: psa-restricted-violations (3 resources affected)</summary>

## Why This Matters

Running as root inside a container means that any container escape vulnerability immediately grants root access on the host node. Even without an escape, root inside the container can modify sensitive files, install packages, and access capabilities that non-root users cannot.

## How to Fix

Set `runAsNonRoot: true` and specify a non-root user ID in the security context:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
```

Set this at the pod level to apply to all containers. Ensure your container image supports running as a non-root user (many official images do).

## Learn More

See the Pod Security Standards Restricted profile and CIS Kubernetes Benchmark 5.2.6. Running as non-root is a fundamental container security best practice.

**Affected resources:** kv-e2e-network-deny/Deployment/web, kv-e2e-network-deny/Deployment/web, kv-e2e-network-deny/Deployment/web

</details>

<details>
<summary>Remediation: read-only-rootfs (1 resources affected)</summary>

## Why This Matters

A writable root filesystem allows an attacker who gains code execution in your container to modify application binaries, install attack tools, plant backdoors, or persist malware across container restarts. Making the filesystem read-only eliminates an entire class of post-exploitation techniques.

## How to Fix

Enable a read-only root filesystem and mount writable volumes only where needed:

```yaml
securityContext:
  readOnlyRootFilesystem: true
volumeMounts:
  - name: tmp
    mountPath: /tmp
volumes:
  - name: tmp
    emptyDir: {}
```

Common paths that need write access include /tmp, /var/cache, and /var/run. Mount each as an emptyDir or tmpfs volume rather than making the entire filesystem writable.

## Learn More

This aligns with CIS Benchmark 5.2.4 and the defense-in-depth principle. Combined with dropping capabilities and running as non-root, a read-only filesystem forms a strong container hardening baseline.

**Affected resources:** kv-e2e-network-deny/Deployment/web

</details>

<details>
<summary>Remediation: resource-limits-missing (1 resources affected)</summary>

## Why This Matters

Without resource limits, a single container can consume all available CPU and memory on a node, starving other workloads and triggering cascading failures. An attacker who compromises an unlimited container can mount a denial-of-service attack against the entire node with a simple fork bomb or memory allocation loop.

## How to Fix

Set both CPU and memory limits based on your application's actual resource usage:

```yaml
resources:
  limits:
    cpu: 500m
    memory: 256Mi
  requests:
    cpu: 100m
    memory: 128Mi
```

Profile your application under load to determine appropriate values. Set limits to handle peak usage and requests to match steady-state consumption.

## Learn More

Use LimitRange objects to enforce default limits at the namespace level. Resource limits also determine the pod's QoS class: pods with equal requests and limits get Guaranteed QoS and are last to be evicted.

**Affected resources:** kv-e2e-network-deny/Deployment/web

</details>

<details>
<summary>Remediation: resource-requests-missing (1 resources affected)</summary>

## Why This Matters

Resource requests tell the Kubernetes scheduler how much CPU and memory your container needs. Without requests, the scheduler treats the pod as needing zero resources and may pack too many pods onto a single node. This leads to overcommitment, resource contention, throttling, and OOM kills under load.

## How to Fix

Set resource requests based on your application's steady-state usage:

```yaml
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 256Mi
```

Observe your application's actual resource consumption using `kubectl top` or a monitoring tool, then set requests to match the typical steady-state usage.

## Learn More

Resource requests determine the pod's QoS class and scheduling behavior. Pods with requests equal to limits receive Guaranteed QoS. Use Vertical Pod Autoscaler (VPA) to automatically recommend request values.

**Affected resources:** kv-e2e-network-deny/Deployment/web

</details>

<details>
<summary>Remediation: run-as-group (1 resources affected)</summary>

## Why This Matters

Without an explicit runAsGroup, the container process defaults to GID 0 (the root group). Files and sockets owned by the root group become accessible to the container, including potentially sensitive host files if volumes are mounted. This widens the attack surface unnecessarily.

## How to Fix

Set an explicit non-root group in the securityContext:

```yaml
securityContext:
  runAsGroup: 1000
  runAsUser: 1000
  runAsNonRoot: true
```

Ensure the container image's application files and directories are readable by the specified GID. You may need to adjust file ownership in your Dockerfile with `chown`.

## Learn More

This aligns with CIS Benchmark 5.2.6 and the Pod Security Standards "Restricted" profile. Always set runAsUser, runAsGroup, and runAsNonRoot together for comprehensive identity control.

**Affected resources:** kv-e2e-network-deny/Deployment/web

</details>

<details>
<summary>Remediation: seccomp-profile (1 resources affected)</summary>

## Why This Matters

Without a Seccomp profile, containers can invoke any of the 300+ Linux system calls, leaving the entire kernel attack surface exposed. Kernel vulnerabilities in obscure syscalls are a primary vector for container escapes. Seccomp filtering blocks dangerous syscalls that legitimate applications never use.

## How to Fix

Apply a Seccomp profile at the container or pod level:

```yaml
securityContext:
  seccompProfile:
    type: RuntimeDefault
```

The RuntimeDefault profile blocks approximately 50 dangerous syscalls while allowing normal application behavior. For stricter controls, use a custom Localhost profile tailored to your application's needs. Set the profile at the pod level to apply it to all containers.

## Learn More

Seccomp profiles are required by the Pod Security Standards "Restricted" profile and CIS Benchmark 5.7.2. Use tools like `strace` or the Security Profiles Operator to generate custom profiles for your workloads.

**Affected resources:** kv-e2e-network-deny/Deployment/web

</details>

<details>
<summary>Remediation: token-projection-config (1 resources affected)</summary>

## Why This Matters

Without explicit projection configuration, ServiceAccount tokens use Kubernetes defaults: no audience restriction and a long expiration. A stolen token remains valid for an extended period and can be used against any API server endpoint, widening the blast radius of a compromise.

## How to Fix

Add a projected volume with explicit expiration and audience:

```yaml
spec:
  volumes:
    - name: token
      projected:
        sources:
          - serviceAccountToken:
              expirationSeconds: 3600
              audience: my-api
              path: token
  containers:
    - name: app
      volumeMounts:
        - name: token
          mountPath: /var/run/secrets/tokens
          readOnly: true
```

Projected tokens auto-rotate before expiry and are rejected by endpoints outside the specified audience.

## Learn More

See the Kubernetes documentation on projected volumes and service account token volume projection for detailed configuration options.

**Affected resources:** kv-e2e-network-deny/Deployment/web

</details>

<details>
<summary>Remediation: limit-range-missing (1 resources affected)</summary>

## Why This Matters

Without a LimitRange, any container can be created without resource constraints. A single runaway or malicious pod can consume all node CPU and memory, causing denial of service for other workloads on the same node.

## How to Fix

Create a LimitRange in the namespace to set default and maximum resource constraints:

```yaml
apiVersion: v1
kind: LimitRange
metadata:
  name: default-limits
  namespace: my-app
spec:
  limits:
    - type: Container
      default:
        cpu: 500m
        memory: 256Mi
      defaultRequest:
        cpu: 100m
        memory: 128Mi
      max:
        cpu: "2"
        memory: 1Gi
```

Containers that omit resource requests/limits will inherit these defaults automatically.

## Learn More

CIS Kubernetes Benchmark 5.2.1 recommends LimitRanges for resource governance. See https://kubernetes.io/docs/concepts/policy/limit-range/ for configuration details.

**Affected resources:** kv-e2e-network-deny/Namespace/kv-e2e-network-deny

</details>

<details>
<summary>Remediation: resource-quota-missing (1 resources affected)</summary>

## Why This Matters

Without a ResourceQuota, a single namespace can consume the entire cluster's CPU, memory, and storage. This creates a noisy-neighbor problem where one team's workloads starve others, and makes capacity planning impossible.

## How to Fix

Create a ResourceQuota to cap the namespace's total resource consumption:

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: compute-quota
  namespace: my-app
spec:
  hard:
    requests.cpu: "10"
    requests.memory: 20Gi
    limits.cpu: "20"
    limits.memory: 40Gi
    pods: "50"
    services: "10"
```

Tune quota values based on the namespace's actual workload requirements and cluster capacity.

## Learn More

CIS Kubernetes Benchmark 5.2.2 recommends ResourceQuotas for multi-tenant clusters. See https://kubernetes.io/docs/concepts/policy/resource-quotas/ for quota configuration and enforcement behavior.

**Affected resources:** kv-e2e-network-deny/Namespace/kv-e2e-network-deny

</details>

<details>
<summary>Remediation: ephemeral-storage-limits (1 resources affected)</summary>

## Why This Matters

Ephemeral storage includes container logs, emptyDir volumes, and the writable container layer. Without limits, a single container can fill the node's root disk, triggering eviction of all pods on that node and potentially causing a cascading failure across your cluster. This is a common denial-of-service vector.

## How to Fix

Set ephemeral-storage limits alongside your CPU and memory limits:

```yaml
resources:
  limits:
    ephemeral-storage: 1Gi
  requests:
    ephemeral-storage: 500Mi
```

Estimate your application's disk usage from logs, temporary files, and cache data. If your application writes large temporary files, consider using a PersistentVolumeClaim instead of ephemeral storage.

## Learn More

The kubelet evicts pods that exceed their ephemeral-storage limit. Use LimitRange to set default ephemeral-storage limits at the namespace level to catch containers that omit this setting.

**Affected resources:** kv-e2e-network-deny/Deployment/web

</details>

<details>
<summary>Remediation: image-no-digest (1 resources affected)</summary>

## Why This Matters

Image tags are mutable pointers -- a registry administrator or attacker can re-push a different image under the same tag. Without a digest, you have no cryptographic guarantee that the image you deploy is the one you tested.

## How to Fix

Pin images by their SHA-256 content digest for a fully immutable reference:

```yaml
containers:
  - name: app
    image: nginx@sha256:a8281ce420348a01ea6e   # Immutable
```

Use `crane digest nginx:1.25.3` or `skopeo inspect` to resolve a tag to its digest during CI/CD, then commit the pinned reference.

## Learn More

SLSA Level 1+ and NIST SP 800-190 recommend digest pinning for container supply chain integrity. See the Kubernetes images documentation for details.

**Affected resources:** kv-e2e-network-deny/Deployment/web

</details>

<details>
<summary>Remediation: liveness-readiness-probes (2 resources affected)</summary>

## Why This Matters

Without a liveness probe, Kubernetes cannot detect when a container has become unresponsive or deadlocked. The container continues running and consuming resources while failing to serve traffic. Users experience timeouts and errors until someone manually intervenes.

## How to Fix

Add a liveness probe that checks the container's health:

```yaml
containers:
  - name: app
    livenessProbe:
      httpGet:
        path: /healthz
        port: 8080
      initialDelaySeconds: 15
      periodSeconds: 10
      failureThreshold: 3
```

Use `httpGet` for HTTP services, `tcpSocket` for TCP services, or `exec` with a custom health check script for non-network workloads.

## Learn More

See the Kubernetes documentation on container probes. Set initialDelaySeconds high enough for your application to start, and consider adding a startupProbe for slow-starting containers.

**Affected resources:** kv-e2e-network-deny/Deployment/web, kv-e2e-network-deny/Deployment/web

</details>

<details>
<summary>Remediation: priority-class-missing (1 resources affected)</summary>

## Why This Matters

Without a PriorityClass, pods receive default priority (typically 0) and are among the first to be evicted during resource pressure or node maintenance. This means important application workloads may be killed before less critical ones, leading to unpredictable outages.

## How to Fix

Define PriorityClasses for your workloads and assign them appropriately:

```yaml
apiVersion: scheduling.k8s.io/v1
kind: PriorityClass
metadata:
  name: app-medium
value: 100000
---
# Reference in your workload:
spec:
  priorityClassName: app-medium
```

Create a tiered priority scheme (e.g., app-critical: 500000, app-medium: 100000, app-low: 10000) that reflects your workload importance hierarchy.

## Learn More

Refer to the Kubernetes Pod Priority and Preemption documentation. Establishing a consistent priority scheme across namespaces ensures predictable eviction behavior during resource contention.

**Affected resources:** kv-e2e-network-deny/Deployment/web

</details>

<details>
<summary>Remediation: runtime-class (1 resources affected)</summary>

## Why This Matters

Without a RuntimeClass, pods use the default container runtime (typically runc), which shares the host kernel directly with containers. A kernel vulnerability can allow container escape to the host. Sandboxed runtimes like gVisor or Kata Containers add an additional isolation layer that intercepts system calls or runs containers in lightweight VMs.

## How to Fix

Specify a sandboxed RuntimeClass in the pod spec:

```yaml
spec:
  runtimeClassName: gvisor
```

Available RuntimeClasses depend on your cluster configuration. Common options include `gvisor` (user-space kernel), `kata` (micro-VMs), and `firecracker`. Check your cluster's available RuntimeClasses with `kubectl get runtimeclasses`.

## Learn More

Sandboxed runtimes are especially important for multi-tenant clusters and workloads processing untrusted input. They add latency overhead, so evaluate performance requirements. See the Kubernetes RuntimeClass documentation.

**Affected resources:** kv-e2e-network-deny/Deployment/web

</details>

<details>
<summary>Remediation: topology-spread (1 resources affected)</summary>

## Why This Matters

Without topology spread constraints, the scheduler may place all replicas on the same node or in the same availability zone. If that node or zone fails, your entire service goes down despite having multiple replicas. This negates the high-availability benefits of running multiple pods.

## How to Fix

Add topology spread constraints to distribute replicas across failure domains:

```yaml
spec:
  topologySpreadConstraints:
    - maxSkew: 1
      topologyKey: kubernetes.io/hostname
      whenUnsatisfiable: DoNotSchedule
      labelSelector:
        matchLabels:
          app: my-app
    - maxSkew: 1
      topologyKey: topology.kubernetes.io/zone
      whenUnsatisfiable: ScheduleAnyway
```

Use `kubernetes.io/hostname` for node-level spreading and `topology.kubernetes.io/zone` for zone-level spreading.

## Learn More

See the Kubernetes Pod Topology Spread Constraints documentation. Combining hostname and zone constraints provides both node-level and zone-level fault tolerance.

**Affected resources:** kv-e2e-network-deny/Deployment/web

</details>

### kv-e2e-psa (28 findings — 🟠5 🟡14 🔵9)

| Severity | Check | Resources | Message | Frameworks |
|----------|-------|-----------|---------|-----------|
| 🟠 High | network-policy-missing | kv-e2e-psa/Namespace/kv-e2e-psa | Namespace "kv-e2e-psa" has no NetworkPolicy defined. All pods are unrestricted. | CIS 5.3.2 · MITRE T1046 · NSA 4.1 · NSA 4.2 |
| 🟠 High | automount-token | kv-e2e-psa/Deployment/unprotected-app | Deployment "unprotected-app" auto-mounts a ServiceAccount token. Most workloads do not need Kubernetes API access. | CIS 5.1.6 · MITRE T1552.007 · NSA 3.2 |
| 🟠 High | default-service-account | kv-e2e-psa/Deployment/unprotected-app | Deployment "unprotected-app" uses the default ServiceAccount, which may have unintended permissions. | CIS 5.1.5 · CIS 5.1.6 · MITRE T1078.001 · NSA 3.1 · NSA 3.2 |
| 🟠 High | privilege-escalation | kv-e2e-psa/Deployment/unprotected-app (pause) | Container "pause" does not set allowPrivilegeEscalation to false, permitting privilege escalation. | CIS 5.2.6 · MITRE T1068 · MITRE T1611 · NSA 1.1 · NSA 2.1 |
| 🟠 High | run-as-root | kv-e2e-psa/Deployment/unprotected-app (pause) | Container "pause" does not set runAsNonRoot: true and may run as root. | CIS 5.2.7 · MITRE T1611 · NSA 1.1 |
| 🟡 Medium | network-policy-egress-unrestricted | kv-e2e-psa/Namespace/kv-e2e-psa | Namespace "kv-e2e-psa" has no NetworkPolicy with egress restrictions. Pods can reach any external destination. | CIS 5.3.2 · MITRE T1048 · NSA 4.2 |
| 🟡 Medium | psa-labels-missing | kv-e2e-psa/Namespace/kv-e2e-psa | Namespace "kv-e2e-psa" is missing the pod-security.kubernetes.io/enforce label; pod security is not enforced. | CIS 5.2.1 · MITRE T1610 · NSA 2.1 |
| 🟡 Medium | apparmor-profile | kv-e2e-psa/Deployment/unprotected-app (pause) | Container "pause" does not have an AppArmor profile set. | CIS 5.6.3 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | capabilities-not-dropped | kv-e2e-psa/Deployment/unprotected-app (pause) | Container "pause" does not drop ALL capabilities, leaving it with unnecessary default privileges. | CIS 5.2.8 · CIS 5.2.10 · MITRE T1068 · NSA 1.1 |
| 🟡 Medium | image-pull-policy | kv-e2e-psa/Deployment/unprotected-app (pause) | Container "pause" uses a mutable image tag with pullPolicy "IfNotPresent" (image: registry.k8s.io/pause:3.9), risking stale images. | CIS 5.5.1 · MITRE T1525 · NSA 1.4 |
| 🟡 Medium | psa-restricted-violations | **3 resources** | Deployment "unprotected-app" container "pause" violates PSS Restricted: runAsNonRoot is not true. | CIS 5.2.1 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | read-only-rootfs | kv-e2e-psa/Deployment/unprotected-app (pause) | Container "pause" does not have a read-only root filesystem. | CIS 5.6.3 · MITRE T1565.001 · NSA 1.2 |
| 🟡 Medium | resource-limits-missing | kv-e2e-psa/Deployment/unprotected-app (pause) | Container "pause" is missing both CPU and memory limits. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🟡 Medium | resource-requests-missing | kv-e2e-psa/Deployment/unprotected-app (pause) | Container "pause" is missing both CPU and memory requests. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🟡 Medium | run-as-group | kv-e2e-psa/Deployment/unprotected-app (pause) | Container "pause" does not set runAsGroup; the process will run as GID 0 (root group) by default. | CIS 5.2.7 · MITRE T1068 · NSA 1.1 |
| 🟡 Medium | seccomp-profile | kv-e2e-psa/Deployment/unprotected-app (pause) | Container "pause" does not have a Seccomp profile set at either the container or pod level. | CIS 5.6.2 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | token-projection-config | kv-e2e-psa/Deployment/unprotected-app | Deployment "unprotected-app" does not use explicitly configured projected ServiceAccount tokens with expiry and audience restrictions. | CIS 5.1.6 · MITRE T1552.007 · NSA 3.2 |
| 🔵 Low | limit-range-missing | kv-e2e-psa/Namespace/kv-e2e-psa | Namespace "kv-e2e-psa" has no LimitRange defined. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | resource-quota-missing | kv-e2e-psa/Namespace/kv-e2e-psa | Namespace "kv-e2e-psa" has no ResourceQuota defined. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | ephemeral-storage-limits | kv-e2e-psa/Deployment/unprotected-app (pause) | Container "pause" is missing ephemeral-storage limits. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | image-no-digest | kv-e2e-psa/Deployment/unprotected-app (pause) | Container "pause" image is not pinned by digest (image: registry.k8s.io/pause:3.9), allowing tag mutation. | CIS 5.5.1 · MITRE T1525 · NSA 1.4 |
| 🔵 Low | liveness-readiness-probes | **2 resources** | Container "pause" has no liveness probe configured. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | priority-class-missing | kv-e2e-psa/Deployment/unprotected-app | Deployment "unprotected-app" has no PriorityClass set; it will be evicted first during resource pressure. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | runtime-class | kv-e2e-psa/Deployment/unprotected-app | Pod "unprotected-app" does not specify a RuntimeClass, using the default (unsandboxed) runtime. | CIS 5.6.3 · MITRE T1611 · NSA 2.1 |
| 🔵 Low | topology-spread | kv-e2e-psa/Deployment/unprotected-app | Deployment "unprotected-app" has no topology spread constraints; all replicas may be scheduled on the same node. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |

<details>
<summary>psa-restricted-violations: 3 affected resources</summary>

- `kv-e2e-psa/Deployment/unprotected-app (pause)`
- `kv-e2e-psa/Deployment/unprotected-app (pause)`
- `kv-e2e-psa/Deployment/unprotected-app (pause)`

</details>

<details>
<summary>liveness-readiness-probes: 2 affected resources</summary>

- `kv-e2e-psa/Deployment/unprotected-app (pause)`
- `kv-e2e-psa/Deployment/unprotected-app (pause)`

</details>

<details>
<summary>Remediation: network-policy-missing (1 resources affected)</summary>

## Why This Matters

Without NetworkPolicies, every pod in this namespace can communicate freely with every other pod in the cluster. If an attacker compromises a single pod, they can move laterally to databases, internal APIs, and other sensitive services with no network-level barriers.

## How to Fix

Create a default-deny NetworkPolicy for the namespace, then add targeted allow rules for legitimate traffic:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: my-namespace
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
```

After applying the default-deny, create additional NetworkPolicy resources that whitelist only the specific ingress and egress flows your workloads require.

## Learn More

See the Kubernetes documentation on NetworkPolicies and CIS Kubernetes Benchmark 5.3.2. A CNI plugin that supports NetworkPolicy (Calico, Cilium, Weave Net) must be installed for policies to take effect.

**Affected resources:** kv-e2e-psa/Namespace/kv-e2e-psa

</details>

<details>
<summary>Remediation: automount-token (1 resources affected)</summary>

## Why This Matters

When a ServiceAccount token is auto-mounted, every container in the pod can call the Kubernetes API. If a container is compromised through a vulnerability or misconfiguration, the attacker gains API access to enumerate resources, read secrets, or escalate privileges.

## How to Fix

Disable auto-mounting at the pod spec level for workloads that do not need API access:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      automountServiceAccountToken: false
      containers:
        - name: app
          image: my-app:latest
```

For workloads that do require API access, use projected tokens with bounded lifetime and audience restrictions instead of the default long-lived token.

## Learn More

Refer to the Kubernetes documentation on configuring service accounts for pods and CIS Kubernetes Benchmark 5.1.6 for auto-mount token guidance.

**Affected resources:** kv-e2e-psa/Deployment/unprotected-app

</details>

<details>
<summary>Remediation: default-service-account (1 resources affected)</summary>

## Why This Matters

The default ServiceAccount is shared by every pod in a namespace. If any pod is compromised, the attacker inherits whatever permissions have been granted to the default account via role bindings, enabling lateral movement across all workloads sharing it.

## How to Fix

Create a dedicated ServiceAccount for each workload and reference it in the pod spec:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-app
  namespace: production
automountServiceAccountToken: false
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      serviceAccountName: my-app
```

Grant only the permissions the workload actually needs via a dedicated Role and RoleBinding.

## Learn More

See the Kubernetes documentation on managing service accounts and CIS Kubernetes Benchmark 5.1.5 for guidance on ensuring default service accounts are not actively used.

**Affected resources:** kv-e2e-psa/Deployment/unprotected-app

</details>

<details>
<summary>Remediation: privilege-escalation (1 resources affected)</summary>

## Why This Matters

By default, Kubernetes allows containers to escalate privileges via setuid/setgid binaries, which let a process gain more permissions than its parent. An attacker can exploit this using setuid binaries already present in the container image (like `su`, `sudo`, or `ping`) to elevate from a low-privilege user to root.

## How to Fix

Explicitly disable privilege escalation in the container's securityContext:

```yaml
securityContext:
  allowPrivilegeEscalation: false
  runAsNonRoot: true
  capabilities:
    drop: ["ALL"]
```

This blocks the use of setuid/setgid binaries and prevents the no_new_privs Linux flag from being cleared. The vast majority of application containers do not need privilege escalation.

## Learn More

This is required by the Pod Security Standards "Restricted" profile and CIS Benchmark 5.2.5. Disabling privilege escalation is one of the most impactful single-line security improvements you can make.

**Affected resources:** kv-e2e-psa/Deployment/unprotected-app

</details>

<details>
<summary>Remediation: run-as-root (1 resources affected)</summary>

## Why This Matters

Without `runAsNonRoot: true`, Kubernetes does not enforce non-root execution and the container may default to running as UID 0 depending on the image's USER directive. If the image defaults to root, the container process gains full privileges, increasing the blast radius of any compromise or container escape.

## How to Fix

Enforce non-root execution in the securityContext:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
```

With `runAsNonRoot: true`, Kubernetes will reject the pod at admission time if the container image attempts to run as root. Setting an explicit `runAsUser` provides an additional guarantee.

## Learn More

This aligns with CIS Benchmark 5.2.6 and the Pod Security Standards "Restricted" profile. The `runAsNonRoot` field acts as a safety net even when images change their default USER.

**Affected resources:** kv-e2e-psa/Deployment/unprotected-app

</details>

<details>
<summary>Remediation: network-policy-egress-unrestricted (1 resources affected)</summary>

## Why This Matters

Without any egress NetworkPolicy in this namespace, pods can freely send traffic to any destination including the public internet. A compromised pod can exfiltrate sensitive data, reach cloud metadata services (e.g., 169.254.169.254), or establish reverse shells to attacker-controlled servers.

## How to Fix

Create a NetworkPolicy with `Egress` in `policyTypes` to restrict outbound traffic. At minimum, allow DNS resolution:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-egress
  namespace: my-namespace
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector: {}
      ports:
        - port: 53
          protocol: UDP
```

Add additional egress rules for specific services your workloads need to reach.

## Learn More

See the Kubernetes NetworkPolicy documentation and CIS Kubernetes Benchmark 5.3.2. Egress controls are a key defense-in-depth measure recommended by the NSA/CISA Kubernetes Hardening Guide.

**Affected resources:** kv-e2e-psa/Namespace/kv-e2e-psa

</details>

<details>
<summary>Remediation: psa-labels-missing (1 resources affected)</summary>

## Why This Matters

Without PSA enforcement labels, any pod configuration is allowed in this namespace, including privileged containers, host namespace access, and root execution. This bypasses Kubernetes' built-in Pod Security Standards and leaves the namespace vulnerable to workloads that could compromise the node.

## How to Fix

Add Pod Security Admission labels to enforce a security profile on all pods in the namespace:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: kv-e2e-psa
  labels:
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

Start with `baseline` enforcement to block known privilege escalations, then upgrade to `restricted` after verifying all workloads are compliant.

## Learn More

See the Kubernetes Pod Security Admission documentation and CIS Kubernetes Benchmark 5.2. The three-tier approach (enforce, audit, warn) allows gradual adoption of stricter profiles.

**Affected resources:** kv-e2e-psa/Namespace/kv-e2e-psa

</details>

<details>
<summary>Remediation: apparmor-profile (1 resources affected)</summary>

## Why This Matters

AppArmor provides mandatory access control (MAC) that restricts which files, network resources, and capabilities a container process can access. Without an AppArmor profile, the container operates without these restrictions, allowing an attacker with code execution to access any file the container user can read and make unrestricted network connections.

## How to Fix

Apply an AppArmor profile in the container's securityContext (Kubernetes 1.30+):

```yaml
securityContext:
  appArmorProfile:
    type: RuntimeDefault
```

The RuntimeDefault profile provides sensible restrictions for most applications. For tighter control, create a custom Localhost profile that only allows the specific file and network access your application needs.

## Learn More

AppArmor is available on Debian/Ubuntu-based nodes. RHEL/CentOS nodes use SELinux instead. Both provide MAC enforcement. Refer to CIS Benchmark 5.7.5 and the Kubernetes AppArmor documentation.

**Affected resources:** kv-e2e-psa/Deployment/unprotected-app

</details>

<details>
<summary>Remediation: capabilities-not-dropped (1 resources affected)</summary>

## Why This Matters

By default, containers receive a set of Linux capabilities including KILL, SETUID, SETGID, and NET_RAW. These defaults are rarely needed by application code and significantly increase the potential damage from a container compromise. Dropping all capabilities follows the principle of least privilege.

## How to Fix

Explicitly drop all capabilities and selectively add back only what your application needs:

```yaml
securityContext:
  capabilities:
    drop: ["ALL"]
    add: ["NET_BIND_SERVICE"]  # Only if needed
```

Most web applications, API servers, and background workers run perfectly with all capabilities dropped. Test your application after making this change to confirm no functionality is lost.

## Learn More

This is required by the Pod Security Standards "Restricted" profile and aligns with CIS Benchmark 5.2.7. Kubernetes best practice is to treat capability grants as exceptions that require explicit justification.

**Affected resources:** kv-e2e-psa/Deployment/unprotected-app

</details>

<details>
<summary>Remediation: image-pull-policy (1 resources affected)</summary>

## Why This Matters

When a mutable image tag is used without `imagePullPolicy: Always`, Kubernetes may serve a cached version of the image from the node. If the tag has been updated in the registry (with a security patch or -- worse -- a compromised layer), the running container will not reflect those changes.

## How to Fix

Set `imagePullPolicy: Always` for any container using a mutable tag:

```yaml
containers:
  - name: app
    image: nginx:1.25.3
    imagePullPolicy: Always   # Forces fresh pull each time
```

Alternatively, pin images by digest (`image@sha256:...`), which makes the pull policy irrelevant because the content is immutable.

## Learn More

See the Kubernetes documentation on image pull policies and CIS Kubernetes Benchmark 5.4.2 for pull policy guidance.

**Affected resources:** kv-e2e-psa/Deployment/unprotected-app

</details>

<details>
<summary>Remediation: psa-restricted-violations (3 resources affected)</summary>

## Why This Matters

Running as root inside a container means that any container escape vulnerability immediately grants root access on the host node. Even without an escape, root inside the container can modify sensitive files, install packages, and access capabilities that non-root users cannot.

## How to Fix

Set `runAsNonRoot: true` and specify a non-root user ID in the security context:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
```

Set this at the pod level to apply to all containers. Ensure your container image supports running as a non-root user (many official images do).

## Learn More

See the Pod Security Standards Restricted profile and CIS Kubernetes Benchmark 5.2.6. Running as non-root is a fundamental container security best practice.

**Affected resources:** kv-e2e-psa/Deployment/unprotected-app, kv-e2e-psa/Deployment/unprotected-app, kv-e2e-psa/Deployment/unprotected-app

</details>

<details>
<summary>Remediation: read-only-rootfs (1 resources affected)</summary>

## Why This Matters

A writable root filesystem allows an attacker who gains code execution in your container to modify application binaries, install attack tools, plant backdoors, or persist malware across container restarts. Making the filesystem read-only eliminates an entire class of post-exploitation techniques.

## How to Fix

Enable a read-only root filesystem and mount writable volumes only where needed:

```yaml
securityContext:
  readOnlyRootFilesystem: true
volumeMounts:
  - name: tmp
    mountPath: /tmp
volumes:
  - name: tmp
    emptyDir: {}
```

Common paths that need write access include /tmp, /var/cache, and /var/run. Mount each as an emptyDir or tmpfs volume rather than making the entire filesystem writable.

## Learn More

This aligns with CIS Benchmark 5.2.4 and the defense-in-depth principle. Combined with dropping capabilities and running as non-root, a read-only filesystem forms a strong container hardening baseline.

**Affected resources:** kv-e2e-psa/Deployment/unprotected-app

</details>

<details>
<summary>Remediation: resource-limits-missing (1 resources affected)</summary>

## Why This Matters

Without resource limits, a single container can consume all available CPU and memory on a node, starving other workloads and triggering cascading failures. An attacker who compromises an unlimited container can mount a denial-of-service attack against the entire node with a simple fork bomb or memory allocation loop.

## How to Fix

Set both CPU and memory limits based on your application's actual resource usage:

```yaml
resources:
  limits:
    cpu: 500m
    memory: 256Mi
  requests:
    cpu: 100m
    memory: 128Mi
```

Profile your application under load to determine appropriate values. Set limits to handle peak usage and requests to match steady-state consumption.

## Learn More

Use LimitRange objects to enforce default limits at the namespace level. Resource limits also determine the pod's QoS class: pods with equal requests and limits get Guaranteed QoS and are last to be evicted.

**Affected resources:** kv-e2e-psa/Deployment/unprotected-app

</details>

<details>
<summary>Remediation: resource-requests-missing (1 resources affected)</summary>

## Why This Matters

Resource requests tell the Kubernetes scheduler how much CPU and memory your container needs. Without requests, the scheduler treats the pod as needing zero resources and may pack too many pods onto a single node. This leads to overcommitment, resource contention, throttling, and OOM kills under load.

## How to Fix

Set resource requests based on your application's steady-state usage:

```yaml
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 256Mi
```

Observe your application's actual resource consumption using `kubectl top` or a monitoring tool, then set requests to match the typical steady-state usage.

## Learn More

Resource requests determine the pod's QoS class and scheduling behavior. Pods with requests equal to limits receive Guaranteed QoS. Use Vertical Pod Autoscaler (VPA) to automatically recommend request values.

**Affected resources:** kv-e2e-psa/Deployment/unprotected-app

</details>

<details>
<summary>Remediation: run-as-group (1 resources affected)</summary>

## Why This Matters

Without an explicit runAsGroup, the container process defaults to GID 0 (the root group). Files and sockets owned by the root group become accessible to the container, including potentially sensitive host files if volumes are mounted. This widens the attack surface unnecessarily.

## How to Fix

Set an explicit non-root group in the securityContext:

```yaml
securityContext:
  runAsGroup: 1000
  runAsUser: 1000
  runAsNonRoot: true
```

Ensure the container image's application files and directories are readable by the specified GID. You may need to adjust file ownership in your Dockerfile with `chown`.

## Learn More

This aligns with CIS Benchmark 5.2.6 and the Pod Security Standards "Restricted" profile. Always set runAsUser, runAsGroup, and runAsNonRoot together for comprehensive identity control.

**Affected resources:** kv-e2e-psa/Deployment/unprotected-app

</details>

<details>
<summary>Remediation: seccomp-profile (1 resources affected)</summary>

## Why This Matters

Without a Seccomp profile, containers can invoke any of the 300+ Linux system calls, leaving the entire kernel attack surface exposed. Kernel vulnerabilities in obscure syscalls are a primary vector for container escapes. Seccomp filtering blocks dangerous syscalls that legitimate applications never use.

## How to Fix

Apply a Seccomp profile at the container or pod level:

```yaml
securityContext:
  seccompProfile:
    type: RuntimeDefault
```

The RuntimeDefault profile blocks approximately 50 dangerous syscalls while allowing normal application behavior. For stricter controls, use a custom Localhost profile tailored to your application's needs. Set the profile at the pod level to apply it to all containers.

## Learn More

Seccomp profiles are required by the Pod Security Standards "Restricted" profile and CIS Benchmark 5.7.2. Use tools like `strace` or the Security Profiles Operator to generate custom profiles for your workloads.

**Affected resources:** kv-e2e-psa/Deployment/unprotected-app

</details>

<details>
<summary>Remediation: token-projection-config (1 resources affected)</summary>

## Why This Matters

Without explicit projection configuration, ServiceAccount tokens use Kubernetes defaults: no audience restriction and a long expiration. A stolen token remains valid for an extended period and can be used against any API server endpoint, widening the blast radius of a compromise.

## How to Fix

Add a projected volume with explicit expiration and audience:

```yaml
spec:
  volumes:
    - name: token
      projected:
        sources:
          - serviceAccountToken:
              expirationSeconds: 3600
              audience: my-api
              path: token
  containers:
    - name: app
      volumeMounts:
        - name: token
          mountPath: /var/run/secrets/tokens
          readOnly: true
```

Projected tokens auto-rotate before expiry and are rejected by endpoints outside the specified audience.

## Learn More

See the Kubernetes documentation on projected volumes and service account token volume projection for detailed configuration options.

**Affected resources:** kv-e2e-psa/Deployment/unprotected-app

</details>

<details>
<summary>Remediation: limit-range-missing (1 resources affected)</summary>

## Why This Matters

Without a LimitRange, any container can be created without resource constraints. A single runaway or malicious pod can consume all node CPU and memory, causing denial of service for other workloads on the same node.

## How to Fix

Create a LimitRange in the namespace to set default and maximum resource constraints:

```yaml
apiVersion: v1
kind: LimitRange
metadata:
  name: default-limits
  namespace: my-app
spec:
  limits:
    - type: Container
      default:
        cpu: 500m
        memory: 256Mi
      defaultRequest:
        cpu: 100m
        memory: 128Mi
      max:
        cpu: "2"
        memory: 1Gi
```

Containers that omit resource requests/limits will inherit these defaults automatically.

## Learn More

CIS Kubernetes Benchmark 5.2.1 recommends LimitRanges for resource governance. See https://kubernetes.io/docs/concepts/policy/limit-range/ for configuration details.

**Affected resources:** kv-e2e-psa/Namespace/kv-e2e-psa

</details>

<details>
<summary>Remediation: resource-quota-missing (1 resources affected)</summary>

## Why This Matters

Without a ResourceQuota, a single namespace can consume the entire cluster's CPU, memory, and storage. This creates a noisy-neighbor problem where one team's workloads starve others, and makes capacity planning impossible.

## How to Fix

Create a ResourceQuota to cap the namespace's total resource consumption:

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: compute-quota
  namespace: my-app
spec:
  hard:
    requests.cpu: "10"
    requests.memory: 20Gi
    limits.cpu: "20"
    limits.memory: 40Gi
    pods: "50"
    services: "10"
```

Tune quota values based on the namespace's actual workload requirements and cluster capacity.

## Learn More

CIS Kubernetes Benchmark 5.2.2 recommends ResourceQuotas for multi-tenant clusters. See https://kubernetes.io/docs/concepts/policy/resource-quotas/ for quota configuration and enforcement behavior.

**Affected resources:** kv-e2e-psa/Namespace/kv-e2e-psa

</details>

<details>
<summary>Remediation: ephemeral-storage-limits (1 resources affected)</summary>

## Why This Matters

Ephemeral storage includes container logs, emptyDir volumes, and the writable container layer. Without limits, a single container can fill the node's root disk, triggering eviction of all pods on that node and potentially causing a cascading failure across your cluster. This is a common denial-of-service vector.

## How to Fix

Set ephemeral-storage limits alongside your CPU and memory limits:

```yaml
resources:
  limits:
    ephemeral-storage: 1Gi
  requests:
    ephemeral-storage: 500Mi
```

Estimate your application's disk usage from logs, temporary files, and cache data. If your application writes large temporary files, consider using a PersistentVolumeClaim instead of ephemeral storage.

## Learn More

The kubelet evicts pods that exceed their ephemeral-storage limit. Use LimitRange to set default ephemeral-storage limits at the namespace level to catch containers that omit this setting.

**Affected resources:** kv-e2e-psa/Deployment/unprotected-app

</details>

<details>
<summary>Remediation: image-no-digest (1 resources affected)</summary>

## Why This Matters

Image tags are mutable pointers -- a registry administrator or attacker can re-push a different image under the same tag. Without a digest, you have no cryptographic guarantee that the image you deploy is the one you tested.

## How to Fix

Pin images by their SHA-256 content digest for a fully immutable reference:

```yaml
containers:
  - name: app
    image: nginx@sha256:a8281ce420348a01ea6e   # Immutable
```

Use `crane digest nginx:1.25.3` or `skopeo inspect` to resolve a tag to its digest during CI/CD, then commit the pinned reference.

## Learn More

SLSA Level 1+ and NIST SP 800-190 recommend digest pinning for container supply chain integrity. See the Kubernetes images documentation for details.

**Affected resources:** kv-e2e-psa/Deployment/unprotected-app

</details>

<details>
<summary>Remediation: liveness-readiness-probes (2 resources affected)</summary>

## Why This Matters

Without a liveness probe, Kubernetes cannot detect when a container has become unresponsive or deadlocked. The container continues running and consuming resources while failing to serve traffic. Users experience timeouts and errors until someone manually intervenes.

## How to Fix

Add a liveness probe that checks the container's health:

```yaml
containers:
  - name: app
    livenessProbe:
      httpGet:
        path: /healthz
        port: 8080
      initialDelaySeconds: 15
      periodSeconds: 10
      failureThreshold: 3
```

Use `httpGet` for HTTP services, `tcpSocket` for TCP services, or `exec` with a custom health check script for non-network workloads.

## Learn More

See the Kubernetes documentation on container probes. Set initialDelaySeconds high enough for your application to start, and consider adding a startupProbe for slow-starting containers.

**Affected resources:** kv-e2e-psa/Deployment/unprotected-app, kv-e2e-psa/Deployment/unprotected-app

</details>

<details>
<summary>Remediation: priority-class-missing (1 resources affected)</summary>

## Why This Matters

Without a PriorityClass, pods receive default priority (typically 0) and are among the first to be evicted during resource pressure or node maintenance. This means important application workloads may be killed before less critical ones, leading to unpredictable outages.

## How to Fix

Define PriorityClasses for your workloads and assign them appropriately:

```yaml
apiVersion: scheduling.k8s.io/v1
kind: PriorityClass
metadata:
  name: app-medium
value: 100000
---
# Reference in your workload:
spec:
  priorityClassName: app-medium
```

Create a tiered priority scheme (e.g., app-critical: 500000, app-medium: 100000, app-low: 10000) that reflects your workload importance hierarchy.

## Learn More

Refer to the Kubernetes Pod Priority and Preemption documentation. Establishing a consistent priority scheme across namespaces ensures predictable eviction behavior during resource contention.

**Affected resources:** kv-e2e-psa/Deployment/unprotected-app

</details>

<details>
<summary>Remediation: runtime-class (1 resources affected)</summary>

## Why This Matters

Without a RuntimeClass, pods use the default container runtime (typically runc), which shares the host kernel directly with containers. A kernel vulnerability can allow container escape to the host. Sandboxed runtimes like gVisor or Kata Containers add an additional isolation layer that intercepts system calls or runs containers in lightweight VMs.

## How to Fix

Specify a sandboxed RuntimeClass in the pod spec:

```yaml
spec:
  runtimeClassName: gvisor
```

Available RuntimeClasses depend on your cluster configuration. Common options include `gvisor` (user-space kernel), `kata` (micro-VMs), and `firecracker`. Check your cluster's available RuntimeClasses with `kubectl get runtimeclasses`.

## Learn More

Sandboxed runtimes are especially important for multi-tenant clusters and workloads processing untrusted input. They add latency overhead, so evaluate performance requirements. See the Kubernetes RuntimeClass documentation.

**Affected resources:** kv-e2e-psa/Deployment/unprotected-app

</details>

<details>
<summary>Remediation: topology-spread (1 resources affected)</summary>

## Why This Matters

Without topology spread constraints, the scheduler may place all replicas on the same node or in the same availability zone. If that node or zone fails, your entire service goes down despite having multiple replicas. This negates the high-availability benefits of running multiple pods.

## How to Fix

Add topology spread constraints to distribute replicas across failure domains:

```yaml
spec:
  topologySpreadConstraints:
    - maxSkew: 1
      topologyKey: kubernetes.io/hostname
      whenUnsatisfiable: DoNotSchedule
      labelSelector:
        matchLabels:
          app: my-app
    - maxSkew: 1
      topologyKey: topology.kubernetes.io/zone
      whenUnsatisfiable: ScheduleAnyway
```

Use `kubernetes.io/hostname` for node-level spreading and `topology.kubernetes.io/zone` for zone-level spreading.

## Learn More

See the Kubernetes Pod Topology Spread Constraints documentation. Combining hostname and zone constraints provides both node-level and zone-level fault tolerance.

**Affected resources:** kv-e2e-psa/Deployment/unprotected-app

</details>

### kv-e2e-psa-audit (29 findings — 🟠5 🟡15 🔵9)

| Severity | Check | Resources | Message | Frameworks |
|----------|-------|-----------|---------|-----------|
| 🟠 High | automount-token | kv-e2e-psa-audit/Deployment/audit-only-app | Deployment "audit-only-app" auto-mounts a ServiceAccount token. Most workloads do not need Kubernetes API access. | CIS 5.1.6 · MITRE T1552.007 · NSA 3.2 |
| 🟠 High | default-service-account | kv-e2e-psa-audit/Deployment/audit-only-app | Deployment "audit-only-app" uses the default ServiceAccount, which may have unintended permissions. | CIS 5.1.5 · CIS 5.1.6 · MITRE T1078.001 · NSA 3.1 · NSA 3.2 |
| 🟠 High | privilege-escalation | kv-e2e-psa-audit/Deployment/audit-only-app (pause) | Container "pause" does not set allowPrivilegeEscalation to false, permitting privilege escalation. | CIS 5.2.6 · MITRE T1068 · MITRE T1611 · NSA 1.1 · NSA 2.1 |
| 🟠 High | run-as-root | kv-e2e-psa-audit/Deployment/audit-only-app (pause) | Container "pause" does not set runAsNonRoot: true and may run as root. | CIS 5.2.7 · MITRE T1611 · NSA 1.1 |
| 🟠 High | network-policy-missing | kv-e2e-psa-audit/Namespace/kv-e2e-psa-audit | Namespace "kv-e2e-psa-audit" has no NetworkPolicy defined. All pods are unrestricted. | CIS 5.3.2 · MITRE T1046 · NSA 4.1 · NSA 4.2 |
| 🟡 Medium | apparmor-profile | kv-e2e-psa-audit/Deployment/audit-only-app (pause) | Container "pause" does not have an AppArmor profile set. | CIS 5.6.3 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | capabilities-not-dropped | kv-e2e-psa-audit/Deployment/audit-only-app (pause) | Container "pause" does not drop ALL capabilities, leaving it with unnecessary default privileges. | CIS 5.2.8 · CIS 5.2.10 · MITRE T1068 · NSA 1.1 |
| 🟡 Medium | image-pull-policy | kv-e2e-psa-audit/Deployment/audit-only-app (pause) | Container "pause" uses a mutable image tag with pullPolicy "IfNotPresent" (image: registry.k8s.io/pause:3.9), risking stale images. | CIS 5.5.1 · MITRE T1525 · NSA 1.4 |
| 🟡 Medium | psa-restricted-violations | **3 resources** | Deployment "audit-only-app" container "pause" violates PSS Restricted: runAsNonRoot is not true. | CIS 5.2.1 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | read-only-rootfs | kv-e2e-psa-audit/Deployment/audit-only-app (pause) | Container "pause" does not have a read-only root filesystem. | CIS 5.6.3 · MITRE T1565.001 · NSA 1.2 |
| 🟡 Medium | resource-limits-missing | kv-e2e-psa-audit/Deployment/audit-only-app (pause) | Container "pause" is missing both CPU and memory limits. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🟡 Medium | resource-requests-missing | kv-e2e-psa-audit/Deployment/audit-only-app (pause) | Container "pause" is missing both CPU and memory requests. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🟡 Medium | run-as-group | kv-e2e-psa-audit/Deployment/audit-only-app (pause) | Container "pause" does not set runAsGroup; the process will run as GID 0 (root group) by default. | CIS 5.2.7 · MITRE T1068 · NSA 1.1 |
| 🟡 Medium | seccomp-profile | kv-e2e-psa-audit/Deployment/audit-only-app (pause) | Container "pause" does not have a Seccomp profile set at either the container or pod level. | CIS 5.6.2 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | token-projection-config | kv-e2e-psa-audit/Deployment/audit-only-app | Deployment "audit-only-app" does not use explicitly configured projected ServiceAccount tokens with expiry and audience restrictions. | CIS 5.1.6 · MITRE T1552.007 · NSA 3.2 |
| 🟡 Medium | network-policy-egress-unrestricted | kv-e2e-psa-audit/Namespace/kv-e2e-psa-audit | Namespace "kv-e2e-psa-audit" has no NetworkPolicy with egress restrictions. Pods can reach any external destination. | CIS 5.3.2 · MITRE T1048 · NSA 4.2 |
| 🟡 Medium | psa-labels-missing | kv-e2e-psa-audit/Namespace/kv-e2e-psa-audit | Namespace "kv-e2e-psa-audit" is missing the pod-security.kubernetes.io/enforce label; pod security is not enforced. | CIS 5.2.1 · MITRE T1610 · NSA 2.1 |
| 🟡 Medium | psa-mode-audit-only | kv-e2e-psa-audit/Namespace/kv-e2e-psa-audit | Namespace "kv-e2e-psa-audit" has PSA audit/warn labels but no enforce label; violations are logged but not blocked. | CIS 5.2.1 · MITRE T1610 · NSA 2.1 |
| 🔵 Low | ephemeral-storage-limits | kv-e2e-psa-audit/Deployment/audit-only-app (pause) | Container "pause" is missing ephemeral-storage limits. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | image-no-digest | kv-e2e-psa-audit/Deployment/audit-only-app (pause) | Container "pause" image is not pinned by digest (image: registry.k8s.io/pause:3.9), allowing tag mutation. | CIS 5.5.1 · MITRE T1525 · NSA 1.4 |
| 🔵 Low | liveness-readiness-probes | **2 resources** | Container "pause" has no liveness probe configured. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | priority-class-missing | kv-e2e-psa-audit/Deployment/audit-only-app | Deployment "audit-only-app" has no PriorityClass set; it will be evicted first during resource pressure. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | runtime-class | kv-e2e-psa-audit/Deployment/audit-only-app | Pod "audit-only-app" does not specify a RuntimeClass, using the default (unsandboxed) runtime. | CIS 5.6.3 · MITRE T1611 · NSA 2.1 |
| 🔵 Low | topology-spread | kv-e2e-psa-audit/Deployment/audit-only-app | Deployment "audit-only-app" has no topology spread constraints; all replicas may be scheduled on the same node. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | limit-range-missing | kv-e2e-psa-audit/Namespace/kv-e2e-psa-audit | Namespace "kv-e2e-psa-audit" has no LimitRange defined. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | resource-quota-missing | kv-e2e-psa-audit/Namespace/kv-e2e-psa-audit | Namespace "kv-e2e-psa-audit" has no ResourceQuota defined. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |

<details>
<summary>psa-restricted-violations: 3 affected resources</summary>

- `kv-e2e-psa-audit/Deployment/audit-only-app (pause)`
- `kv-e2e-psa-audit/Deployment/audit-only-app (pause)`
- `kv-e2e-psa-audit/Deployment/audit-only-app (pause)`

</details>

<details>
<summary>liveness-readiness-probes: 2 affected resources</summary>

- `kv-e2e-psa-audit/Deployment/audit-only-app (pause)`
- `kv-e2e-psa-audit/Deployment/audit-only-app (pause)`

</details>

<details>
<summary>Remediation: automount-token (1 resources affected)</summary>

## Why This Matters

When a ServiceAccount token is auto-mounted, every container in the pod can call the Kubernetes API. If a container is compromised through a vulnerability or misconfiguration, the attacker gains API access to enumerate resources, read secrets, or escalate privileges.

## How to Fix

Disable auto-mounting at the pod spec level for workloads that do not need API access:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      automountServiceAccountToken: false
      containers:
        - name: app
          image: my-app:latest
```

For workloads that do require API access, use projected tokens with bounded lifetime and audience restrictions instead of the default long-lived token.

## Learn More

Refer to the Kubernetes documentation on configuring service accounts for pods and CIS Kubernetes Benchmark 5.1.6 for auto-mount token guidance.

**Affected resources:** kv-e2e-psa-audit/Deployment/audit-only-app

</details>

<details>
<summary>Remediation: default-service-account (1 resources affected)</summary>

## Why This Matters

The default ServiceAccount is shared by every pod in a namespace. If any pod is compromised, the attacker inherits whatever permissions have been granted to the default account via role bindings, enabling lateral movement across all workloads sharing it.

## How to Fix

Create a dedicated ServiceAccount for each workload and reference it in the pod spec:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-app
  namespace: production
automountServiceAccountToken: false
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      serviceAccountName: my-app
```

Grant only the permissions the workload actually needs via a dedicated Role and RoleBinding.

## Learn More

See the Kubernetes documentation on managing service accounts and CIS Kubernetes Benchmark 5.1.5 for guidance on ensuring default service accounts are not actively used.

**Affected resources:** kv-e2e-psa-audit/Deployment/audit-only-app

</details>

<details>
<summary>Remediation: privilege-escalation (1 resources affected)</summary>

## Why This Matters

By default, Kubernetes allows containers to escalate privileges via setuid/setgid binaries, which let a process gain more permissions than its parent. An attacker can exploit this using setuid binaries already present in the container image (like `su`, `sudo`, or `ping`) to elevate from a low-privilege user to root.

## How to Fix

Explicitly disable privilege escalation in the container's securityContext:

```yaml
securityContext:
  allowPrivilegeEscalation: false
  runAsNonRoot: true
  capabilities:
    drop: ["ALL"]
```

This blocks the use of setuid/setgid binaries and prevents the no_new_privs Linux flag from being cleared. The vast majority of application containers do not need privilege escalation.

## Learn More

This is required by the Pod Security Standards "Restricted" profile and CIS Benchmark 5.2.5. Disabling privilege escalation is one of the most impactful single-line security improvements you can make.

**Affected resources:** kv-e2e-psa-audit/Deployment/audit-only-app

</details>

<details>
<summary>Remediation: run-as-root (1 resources affected)</summary>

## Why This Matters

Without `runAsNonRoot: true`, Kubernetes does not enforce non-root execution and the container may default to running as UID 0 depending on the image's USER directive. If the image defaults to root, the container process gains full privileges, increasing the blast radius of any compromise or container escape.

## How to Fix

Enforce non-root execution in the securityContext:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
```

With `runAsNonRoot: true`, Kubernetes will reject the pod at admission time if the container image attempts to run as root. Setting an explicit `runAsUser` provides an additional guarantee.

## Learn More

This aligns with CIS Benchmark 5.2.6 and the Pod Security Standards "Restricted" profile. The `runAsNonRoot` field acts as a safety net even when images change their default USER.

**Affected resources:** kv-e2e-psa-audit/Deployment/audit-only-app

</details>

<details>
<summary>Remediation: network-policy-missing (1 resources affected)</summary>

## Why This Matters

Without NetworkPolicies, every pod in this namespace can communicate freely with every other pod in the cluster. If an attacker compromises a single pod, they can move laterally to databases, internal APIs, and other sensitive services with no network-level barriers.

## How to Fix

Create a default-deny NetworkPolicy for the namespace, then add targeted allow rules for legitimate traffic:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: my-namespace
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
```

After applying the default-deny, create additional NetworkPolicy resources that whitelist only the specific ingress and egress flows your workloads require.

## Learn More

See the Kubernetes documentation on NetworkPolicies and CIS Kubernetes Benchmark 5.3.2. A CNI plugin that supports NetworkPolicy (Calico, Cilium, Weave Net) must be installed for policies to take effect.

**Affected resources:** kv-e2e-psa-audit/Namespace/kv-e2e-psa-audit

</details>

<details>
<summary>Remediation: apparmor-profile (1 resources affected)</summary>

## Why This Matters

AppArmor provides mandatory access control (MAC) that restricts which files, network resources, and capabilities a container process can access. Without an AppArmor profile, the container operates without these restrictions, allowing an attacker with code execution to access any file the container user can read and make unrestricted network connections.

## How to Fix

Apply an AppArmor profile in the container's securityContext (Kubernetes 1.30+):

```yaml
securityContext:
  appArmorProfile:
    type: RuntimeDefault
```

The RuntimeDefault profile provides sensible restrictions for most applications. For tighter control, create a custom Localhost profile that only allows the specific file and network access your application needs.

## Learn More

AppArmor is available on Debian/Ubuntu-based nodes. RHEL/CentOS nodes use SELinux instead. Both provide MAC enforcement. Refer to CIS Benchmark 5.7.5 and the Kubernetes AppArmor documentation.

**Affected resources:** kv-e2e-psa-audit/Deployment/audit-only-app

</details>

<details>
<summary>Remediation: capabilities-not-dropped (1 resources affected)</summary>

## Why This Matters

By default, containers receive a set of Linux capabilities including KILL, SETUID, SETGID, and NET_RAW. These defaults are rarely needed by application code and significantly increase the potential damage from a container compromise. Dropping all capabilities follows the principle of least privilege.

## How to Fix

Explicitly drop all capabilities and selectively add back only what your application needs:

```yaml
securityContext:
  capabilities:
    drop: ["ALL"]
    add: ["NET_BIND_SERVICE"]  # Only if needed
```

Most web applications, API servers, and background workers run perfectly with all capabilities dropped. Test your application after making this change to confirm no functionality is lost.

## Learn More

This is required by the Pod Security Standards "Restricted" profile and aligns with CIS Benchmark 5.2.7. Kubernetes best practice is to treat capability grants as exceptions that require explicit justification.

**Affected resources:** kv-e2e-psa-audit/Deployment/audit-only-app

</details>

<details>
<summary>Remediation: image-pull-policy (1 resources affected)</summary>

## Why This Matters

When a mutable image tag is used without `imagePullPolicy: Always`, Kubernetes may serve a cached version of the image from the node. If the tag has been updated in the registry (with a security patch or -- worse -- a compromised layer), the running container will not reflect those changes.

## How to Fix

Set `imagePullPolicy: Always` for any container using a mutable tag:

```yaml
containers:
  - name: app
    image: nginx:1.25.3
    imagePullPolicy: Always   # Forces fresh pull each time
```

Alternatively, pin images by digest (`image@sha256:...`), which makes the pull policy irrelevant because the content is immutable.

## Learn More

See the Kubernetes documentation on image pull policies and CIS Kubernetes Benchmark 5.4.2 for pull policy guidance.

**Affected resources:** kv-e2e-psa-audit/Deployment/audit-only-app

</details>

<details>
<summary>Remediation: psa-restricted-violations (3 resources affected)</summary>

## Why This Matters

Running as root inside a container means that any container escape vulnerability immediately grants root access on the host node. Even without an escape, root inside the container can modify sensitive files, install packages, and access capabilities that non-root users cannot.

## How to Fix

Set `runAsNonRoot: true` and specify a non-root user ID in the security context:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
```

Set this at the pod level to apply to all containers. Ensure your container image supports running as a non-root user (many official images do).

## Learn More

See the Pod Security Standards Restricted profile and CIS Kubernetes Benchmark 5.2.6. Running as non-root is a fundamental container security best practice.

**Affected resources:** kv-e2e-psa-audit/Deployment/audit-only-app, kv-e2e-psa-audit/Deployment/audit-only-app, kv-e2e-psa-audit/Deployment/audit-only-app

</details>

<details>
<summary>Remediation: read-only-rootfs (1 resources affected)</summary>

## Why This Matters

A writable root filesystem allows an attacker who gains code execution in your container to modify application binaries, install attack tools, plant backdoors, or persist malware across container restarts. Making the filesystem read-only eliminates an entire class of post-exploitation techniques.

## How to Fix

Enable a read-only root filesystem and mount writable volumes only where needed:

```yaml
securityContext:
  readOnlyRootFilesystem: true
volumeMounts:
  - name: tmp
    mountPath: /tmp
volumes:
  - name: tmp
    emptyDir: {}
```

Common paths that need write access include /tmp, /var/cache, and /var/run. Mount each as an emptyDir or tmpfs volume rather than making the entire filesystem writable.

## Learn More

This aligns with CIS Benchmark 5.2.4 and the defense-in-depth principle. Combined with dropping capabilities and running as non-root, a read-only filesystem forms a strong container hardening baseline.

**Affected resources:** kv-e2e-psa-audit/Deployment/audit-only-app

</details>

<details>
<summary>Remediation: resource-limits-missing (1 resources affected)</summary>

## Why This Matters

Without resource limits, a single container can consume all available CPU and memory on a node, starving other workloads and triggering cascading failures. An attacker who compromises an unlimited container can mount a denial-of-service attack against the entire node with a simple fork bomb or memory allocation loop.

## How to Fix

Set both CPU and memory limits based on your application's actual resource usage:

```yaml
resources:
  limits:
    cpu: 500m
    memory: 256Mi
  requests:
    cpu: 100m
    memory: 128Mi
```

Profile your application under load to determine appropriate values. Set limits to handle peak usage and requests to match steady-state consumption.

## Learn More

Use LimitRange objects to enforce default limits at the namespace level. Resource limits also determine the pod's QoS class: pods with equal requests and limits get Guaranteed QoS and are last to be evicted.

**Affected resources:** kv-e2e-psa-audit/Deployment/audit-only-app

</details>

<details>
<summary>Remediation: resource-requests-missing (1 resources affected)</summary>

## Why This Matters

Resource requests tell the Kubernetes scheduler how much CPU and memory your container needs. Without requests, the scheduler treats the pod as needing zero resources and may pack too many pods onto a single node. This leads to overcommitment, resource contention, throttling, and OOM kills under load.

## How to Fix

Set resource requests based on your application's steady-state usage:

```yaml
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 256Mi
```

Observe your application's actual resource consumption using `kubectl top` or a monitoring tool, then set requests to match the typical steady-state usage.

## Learn More

Resource requests determine the pod's QoS class and scheduling behavior. Pods with requests equal to limits receive Guaranteed QoS. Use Vertical Pod Autoscaler (VPA) to automatically recommend request values.

**Affected resources:** kv-e2e-psa-audit/Deployment/audit-only-app

</details>

<details>
<summary>Remediation: run-as-group (1 resources affected)</summary>

## Why This Matters

Without an explicit runAsGroup, the container process defaults to GID 0 (the root group). Files and sockets owned by the root group become accessible to the container, including potentially sensitive host files if volumes are mounted. This widens the attack surface unnecessarily.

## How to Fix

Set an explicit non-root group in the securityContext:

```yaml
securityContext:
  runAsGroup: 1000
  runAsUser: 1000
  runAsNonRoot: true
```

Ensure the container image's application files and directories are readable by the specified GID. You may need to adjust file ownership in your Dockerfile with `chown`.

## Learn More

This aligns with CIS Benchmark 5.2.6 and the Pod Security Standards "Restricted" profile. Always set runAsUser, runAsGroup, and runAsNonRoot together for comprehensive identity control.

**Affected resources:** kv-e2e-psa-audit/Deployment/audit-only-app

</details>

<details>
<summary>Remediation: seccomp-profile (1 resources affected)</summary>

## Why This Matters

Without a Seccomp profile, containers can invoke any of the 300+ Linux system calls, leaving the entire kernel attack surface exposed. Kernel vulnerabilities in obscure syscalls are a primary vector for container escapes. Seccomp filtering blocks dangerous syscalls that legitimate applications never use.

## How to Fix

Apply a Seccomp profile at the container or pod level:

```yaml
securityContext:
  seccompProfile:
    type: RuntimeDefault
```

The RuntimeDefault profile blocks approximately 50 dangerous syscalls while allowing normal application behavior. For stricter controls, use a custom Localhost profile tailored to your application's needs. Set the profile at the pod level to apply it to all containers.

## Learn More

Seccomp profiles are required by the Pod Security Standards "Restricted" profile and CIS Benchmark 5.7.2. Use tools like `strace` or the Security Profiles Operator to generate custom profiles for your workloads.

**Affected resources:** kv-e2e-psa-audit/Deployment/audit-only-app

</details>

<details>
<summary>Remediation: token-projection-config (1 resources affected)</summary>

## Why This Matters

Without explicit projection configuration, ServiceAccount tokens use Kubernetes defaults: no audience restriction and a long expiration. A stolen token remains valid for an extended period and can be used against any API server endpoint, widening the blast radius of a compromise.

## How to Fix

Add a projected volume with explicit expiration and audience:

```yaml
spec:
  volumes:
    - name: token
      projected:
        sources:
          - serviceAccountToken:
              expirationSeconds: 3600
              audience: my-api
              path: token
  containers:
    - name: app
      volumeMounts:
        - name: token
          mountPath: /var/run/secrets/tokens
          readOnly: true
```

Projected tokens auto-rotate before expiry and are rejected by endpoints outside the specified audience.

## Learn More

See the Kubernetes documentation on projected volumes and service account token volume projection for detailed configuration options.

**Affected resources:** kv-e2e-psa-audit/Deployment/audit-only-app

</details>

<details>
<summary>Remediation: network-policy-egress-unrestricted (1 resources affected)</summary>

## Why This Matters

Without any egress NetworkPolicy in this namespace, pods can freely send traffic to any destination including the public internet. A compromised pod can exfiltrate sensitive data, reach cloud metadata services (e.g., 169.254.169.254), or establish reverse shells to attacker-controlled servers.

## How to Fix

Create a NetworkPolicy with `Egress` in `policyTypes` to restrict outbound traffic. At minimum, allow DNS resolution:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-egress
  namespace: my-namespace
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector: {}
      ports:
        - port: 53
          protocol: UDP
```

Add additional egress rules for specific services your workloads need to reach.

## Learn More

See the Kubernetes NetworkPolicy documentation and CIS Kubernetes Benchmark 5.3.2. Egress controls are a key defense-in-depth measure recommended by the NSA/CISA Kubernetes Hardening Guide.

**Affected resources:** kv-e2e-psa-audit/Namespace/kv-e2e-psa-audit

</details>

<details>
<summary>Remediation: psa-labels-missing (1 resources affected)</summary>

## Why This Matters

Without PSA enforcement labels, any pod configuration is allowed in this namespace, including privileged containers, host namespace access, and root execution. This bypasses Kubernetes' built-in Pod Security Standards and leaves the namespace vulnerable to workloads that could compromise the node.

## How to Fix

Add Pod Security Admission labels to enforce a security profile on all pods in the namespace:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: kv-e2e-psa-audit
  labels:
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

Start with `baseline` enforcement to block known privilege escalations, then upgrade to `restricted` after verifying all workloads are compliant.

## Learn More

See the Kubernetes Pod Security Admission documentation and CIS Kubernetes Benchmark 5.2. The three-tier approach (enforce, audit, warn) allows gradual adoption of stricter profiles.

**Affected resources:** kv-e2e-psa-audit/Namespace/kv-e2e-psa-audit

</details>

<details>
<summary>Remediation: psa-mode-audit-only (1 resources affected)</summary>

## Why This Matters

Audit and warn modes only log violations or show warnings to users -- they do not actually block non-compliant pods from being created. Without the `enforce` label, insecure workloads such as privileged containers or root-running pods can still be admitted to the namespace.

## How to Fix

Add the `enforce` label alongside the existing audit/warn labels to actively block non-compliant pods:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

Set `enforce` to `baseline` initially and review audit logs for `restricted` violations before upgrading the enforcement level.

## Learn More

See the Kubernetes Pod Security Admission documentation on modes (enforce, audit, warn). CIS Kubernetes Benchmark 5.2 recommends active enforcement of Pod Security Standards, not just auditing.

**Affected resources:** kv-e2e-psa-audit/Namespace/kv-e2e-psa-audit

</details>

<details>
<summary>Remediation: ephemeral-storage-limits (1 resources affected)</summary>

## Why This Matters

Ephemeral storage includes container logs, emptyDir volumes, and the writable container layer. Without limits, a single container can fill the node's root disk, triggering eviction of all pods on that node and potentially causing a cascading failure across your cluster. This is a common denial-of-service vector.

## How to Fix

Set ephemeral-storage limits alongside your CPU and memory limits:

```yaml
resources:
  limits:
    ephemeral-storage: 1Gi
  requests:
    ephemeral-storage: 500Mi
```

Estimate your application's disk usage from logs, temporary files, and cache data. If your application writes large temporary files, consider using a PersistentVolumeClaim instead of ephemeral storage.

## Learn More

The kubelet evicts pods that exceed their ephemeral-storage limit. Use LimitRange to set default ephemeral-storage limits at the namespace level to catch containers that omit this setting.

**Affected resources:** kv-e2e-psa-audit/Deployment/audit-only-app

</details>

<details>
<summary>Remediation: image-no-digest (1 resources affected)</summary>

## Why This Matters

Image tags are mutable pointers -- a registry administrator or attacker can re-push a different image under the same tag. Without a digest, you have no cryptographic guarantee that the image you deploy is the one you tested.

## How to Fix

Pin images by their SHA-256 content digest for a fully immutable reference:

```yaml
containers:
  - name: app
    image: nginx@sha256:a8281ce420348a01ea6e   # Immutable
```

Use `crane digest nginx:1.25.3` or `skopeo inspect` to resolve a tag to its digest during CI/CD, then commit the pinned reference.

## Learn More

SLSA Level 1+ and NIST SP 800-190 recommend digest pinning for container supply chain integrity. See the Kubernetes images documentation for details.

**Affected resources:** kv-e2e-psa-audit/Deployment/audit-only-app

</details>

<details>
<summary>Remediation: liveness-readiness-probes (2 resources affected)</summary>

## Why This Matters

Without a liveness probe, Kubernetes cannot detect when a container has become unresponsive or deadlocked. The container continues running and consuming resources while failing to serve traffic. Users experience timeouts and errors until someone manually intervenes.

## How to Fix

Add a liveness probe that checks the container's health:

```yaml
containers:
  - name: app
    livenessProbe:
      httpGet:
        path: /healthz
        port: 8080
      initialDelaySeconds: 15
      periodSeconds: 10
      failureThreshold: 3
```

Use `httpGet` for HTTP services, `tcpSocket` for TCP services, or `exec` with a custom health check script for non-network workloads.

## Learn More

See the Kubernetes documentation on container probes. Set initialDelaySeconds high enough for your application to start, and consider adding a startupProbe for slow-starting containers.

**Affected resources:** kv-e2e-psa-audit/Deployment/audit-only-app, kv-e2e-psa-audit/Deployment/audit-only-app

</details>

<details>
<summary>Remediation: priority-class-missing (1 resources affected)</summary>

## Why This Matters

Without a PriorityClass, pods receive default priority (typically 0) and are among the first to be evicted during resource pressure or node maintenance. This means important application workloads may be killed before less critical ones, leading to unpredictable outages.

## How to Fix

Define PriorityClasses for your workloads and assign them appropriately:

```yaml
apiVersion: scheduling.k8s.io/v1
kind: PriorityClass
metadata:
  name: app-medium
value: 100000
---
# Reference in your workload:
spec:
  priorityClassName: app-medium
```

Create a tiered priority scheme (e.g., app-critical: 500000, app-medium: 100000, app-low: 10000) that reflects your workload importance hierarchy.

## Learn More

Refer to the Kubernetes Pod Priority and Preemption documentation. Establishing a consistent priority scheme across namespaces ensures predictable eviction behavior during resource contention.

**Affected resources:** kv-e2e-psa-audit/Deployment/audit-only-app

</details>

<details>
<summary>Remediation: runtime-class (1 resources affected)</summary>

## Why This Matters

Without a RuntimeClass, pods use the default container runtime (typically runc), which shares the host kernel directly with containers. A kernel vulnerability can allow container escape to the host. Sandboxed runtimes like gVisor or Kata Containers add an additional isolation layer that intercepts system calls or runs containers in lightweight VMs.

## How to Fix

Specify a sandboxed RuntimeClass in the pod spec:

```yaml
spec:
  runtimeClassName: gvisor
```

Available RuntimeClasses depend on your cluster configuration. Common options include `gvisor` (user-space kernel), `kata` (micro-VMs), and `firecracker`. Check your cluster's available RuntimeClasses with `kubectl get runtimeclasses`.

## Learn More

Sandboxed runtimes are especially important for multi-tenant clusters and workloads processing untrusted input. They add latency overhead, so evaluate performance requirements. See the Kubernetes RuntimeClass documentation.

**Affected resources:** kv-e2e-psa-audit/Deployment/audit-only-app

</details>

<details>
<summary>Remediation: topology-spread (1 resources affected)</summary>

## Why This Matters

Without topology spread constraints, the scheduler may place all replicas on the same node or in the same availability zone. If that node or zone fails, your entire service goes down despite having multiple replicas. This negates the high-availability benefits of running multiple pods.

## How to Fix

Add topology spread constraints to distribute replicas across failure domains:

```yaml
spec:
  topologySpreadConstraints:
    - maxSkew: 1
      topologyKey: kubernetes.io/hostname
      whenUnsatisfiable: DoNotSchedule
      labelSelector:
        matchLabels:
          app: my-app
    - maxSkew: 1
      topologyKey: topology.kubernetes.io/zone
      whenUnsatisfiable: ScheduleAnyway
```

Use `kubernetes.io/hostname` for node-level spreading and `topology.kubernetes.io/zone` for zone-level spreading.

## Learn More

See the Kubernetes Pod Topology Spread Constraints documentation. Combining hostname and zone constraints provides both node-level and zone-level fault tolerance.

**Affected resources:** kv-e2e-psa-audit/Deployment/audit-only-app

</details>

<details>
<summary>Remediation: limit-range-missing (1 resources affected)</summary>

## Why This Matters

Without a LimitRange, any container can be created without resource constraints. A single runaway or malicious pod can consume all node CPU and memory, causing denial of service for other workloads on the same node.

## How to Fix

Create a LimitRange in the namespace to set default and maximum resource constraints:

```yaml
apiVersion: v1
kind: LimitRange
metadata:
  name: default-limits
  namespace: my-app
spec:
  limits:
    - type: Container
      default:
        cpu: 500m
        memory: 256Mi
      defaultRequest:
        cpu: 100m
        memory: 128Mi
      max:
        cpu: "2"
        memory: 1Gi
```

Containers that omit resource requests/limits will inherit these defaults automatically.

## Learn More

CIS Kubernetes Benchmark 5.2.1 recommends LimitRanges for resource governance. See https://kubernetes.io/docs/concepts/policy/limit-range/ for configuration details.

**Affected resources:** kv-e2e-psa-audit/Namespace/kv-e2e-psa-audit

</details>

<details>
<summary>Remediation: resource-quota-missing (1 resources affected)</summary>

## Why This Matters

Without a ResourceQuota, a single namespace can consume the entire cluster's CPU, memory, and storage. This creates a noisy-neighbor problem where one team's workloads starve others, and makes capacity planning impossible.

## How to Fix

Create a ResourceQuota to cap the namespace's total resource consumption:

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: compute-quota
  namespace: my-app
spec:
  hard:
    requests.cpu: "10"
    requests.memory: 20Gi
    limits.cpu: "20"
    limits.memory: 40Gi
    pods: "50"
    services: "10"
```

Tune quota values based on the namespace's actual workload requirements and cluster capacity.

## Learn More

CIS Kubernetes Benchmark 5.2.2 recommends ResourceQuotas for multi-tenant clusters. See https://kubernetes.io/docs/concepts/policy/resource-quotas/ for quota configuration and enforcement behavior.

**Affected resources:** kv-e2e-psa-audit/Namespace/kv-e2e-psa-audit

</details>

### kv-e2e-psa-baseline (83 findings — 🔴3 🟠18 🟡39 🔵23)

| Severity | Check | Resources | Message | Frameworks |
|----------|-------|-----------|---------|-----------|
| 🔴 Critical | host-network | kv-e2e-psa-baseline/Deployment/host-network-app | Deployment "host-network-app" has hostNetwork enabled, bypassing network policies and exposing the host network. | CIS 5.2.5 · MITRE T1611 · MITRE T1040 · NSA 1.3 · NSA 4.1 |
| 🔴 Critical | host-pid | kv-e2e-psa-baseline/Deployment/privileged-app | Deployment "privileged-app" has hostPID enabled, allowing containers to see all host processes. | CIS 5.2.3 · MITRE T1611 · MITRE T1057 · NSA 1.3 |
| 🔴 Critical | privileged | kv-e2e-psa-baseline/Deployment/privileged-app (pause) | Container "pause" is running in privileged mode, granting full host access. | CIS 5.2.2 · MITRE T1611 · NSA 1.1 · NSA 2.1 |
| 🟠 High | automount-token | **3 resources** | Deployment "dangerous-caps-app" auto-mounts a ServiceAccount token. Most workloads do not need Kubernetes API access. | CIS 5.1.6 · MITRE T1552.007 · NSA 3.2 |
| 🟠 High | capabilities-added | kv-e2e-psa-baseline/Deployment/dangerous-caps-app (pause) | Container "pause" adds dangerous capabilities: SYS_ADMIN. | CIS 5.2.9 · CIS 5.2.10 · MITRE T1611 · MITRE T1068 · NSA 1.1 · NSA 2.1 |
| 🟠 High | default-service-account | **3 resources** | Deployment "dangerous-caps-app" uses the default ServiceAccount, which may have unintended permissions. | CIS 5.1.5 · CIS 5.1.6 · MITRE T1078.001 · NSA 3.1 · NSA 3.2 |
| 🟠 High | privilege-escalation | **3 resources** | Container "pause" does not set allowPrivilegeEscalation to false, permitting privilege escalation. | CIS 5.2.6 · MITRE T1068 · MITRE T1611 · NSA 1.1 · NSA 2.1 |
| 🟠 High | psa-baseline-violations | **4 resources** | Deployment "dangerous-caps-app" container "pause" violates PSS Baseline: adds dangerous capability "SYS_ADMIN". | CIS 5.2.1 · MITRE T1611 · NSA 2.1 |
| 🟠 High | run-as-root | **3 resources** | Container "pause" does not set runAsNonRoot: true and may run as root. | CIS 5.2.7 · MITRE T1611 · NSA 1.1 |
| 🟠 High | network-policy-missing | kv-e2e-psa-baseline/Namespace/kv-e2e-psa-baseline | Namespace "kv-e2e-psa-baseline" has no NetworkPolicy defined. All pods are unrestricted. | CIS 5.3.2 · MITRE T1046 · NSA 4.1 · NSA 4.2 |
| 🟡 Medium | apparmor-profile | **3 resources** | Container "pause" does not have an AppArmor profile set. | CIS 5.6.3 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | capabilities-not-dropped | **3 resources** | Container "pause" does not drop ALL capabilities, leaving it with unnecessary default privileges. | CIS 5.2.8 · CIS 5.2.10 · MITRE T1068 · NSA 1.1 |
| 🟡 Medium | image-pull-policy | **3 resources** | Container "pause" uses a mutable image tag with pullPolicy "IfNotPresent" (image: registry.k8s.io/pause:3.9), risking stale images. | CIS 5.5.1 · MITRE T1525 · NSA 1.4 |
| 🟡 Medium | psa-restricted-violations | **9 resources** | Deployment "dangerous-caps-app" container "pause" violates PSS Restricted: runAsNonRoot is not true. | CIS 5.2.1 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | read-only-rootfs | **3 resources** | Container "pause" does not have a read-only root filesystem. | CIS 5.6.3 · MITRE T1565.001 · NSA 1.2 |
| 🟡 Medium | resource-limits-missing | **3 resources** | Container "pause" is missing both CPU and memory limits. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🟡 Medium | resource-requests-missing | **3 resources** | Container "pause" is missing both CPU and memory requests. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🟡 Medium | run-as-group | **3 resources** | Container "pause" does not set runAsGroup; the process will run as GID 0 (root group) by default. | CIS 5.2.7 · MITRE T1068 · NSA 1.1 |
| 🟡 Medium | seccomp-profile | **3 resources** | Container "pause" does not have a Seccomp profile set at either the container or pod level. | CIS 5.6.2 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | token-projection-config | **3 resources** | Deployment "dangerous-caps-app" does not use explicitly configured projected ServiceAccount tokens with expiry and audience restrictions. | CIS 5.1.6 · MITRE T1552.007 · NSA 3.2 |
| 🟡 Medium | network-policy-egress-unrestricted | kv-e2e-psa-baseline/Namespace/kv-e2e-psa-baseline | Namespace "kv-e2e-psa-baseline" has no NetworkPolicy with egress restrictions. Pods can reach any external destination. | CIS 5.3.2 · MITRE T1048 · NSA 4.2 |
| 🟡 Medium | psa-labels-missing | kv-e2e-psa-baseline/Namespace/kv-e2e-psa-baseline | Namespace "kv-e2e-psa-baseline" is missing the pod-security.kubernetes.io/enforce label; pod security is not enforced. | CIS 5.2.1 · MITRE T1610 · NSA 2.1 |
| 🟡 Medium | psa-mode-audit-only | kv-e2e-psa-baseline/Namespace/kv-e2e-psa-baseline | Namespace "kv-e2e-psa-baseline" has PSA audit/warn labels but no enforce label; violations are logged but not blocked. | CIS 5.2.1 · MITRE T1610 · NSA 2.1 |
| 🔵 Low | ephemeral-storage-limits | **3 resources** | Container "pause" is missing ephemeral-storage limits. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | image-no-digest | **3 resources** | Container "pause" image is not pinned by digest (image: registry.k8s.io/pause:3.9), allowing tag mutation. | CIS 5.5.1 · MITRE T1525 · NSA 1.4 |
| 🔵 Low | liveness-readiness-probes | **6 resources** | Container "pause" has no liveness probe configured. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | priority-class-missing | **3 resources** | Deployment "dangerous-caps-app" has no PriorityClass set; it will be evicted first during resource pressure. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | runtime-class | **3 resources** | Pod "dangerous-caps-app" does not specify a RuntimeClass, using the default (unsandboxed) runtime. | CIS 5.6.3 · MITRE T1611 · NSA 2.1 |
| 🔵 Low | topology-spread | **3 resources** | Deployment "dangerous-caps-app" has no topology spread constraints; all replicas may be scheduled on the same node. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | limit-range-missing | kv-e2e-psa-baseline/Namespace/kv-e2e-psa-baseline | Namespace "kv-e2e-psa-baseline" has no LimitRange defined. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | resource-quota-missing | kv-e2e-psa-baseline/Namespace/kv-e2e-psa-baseline | Namespace "kv-e2e-psa-baseline" has no ResourceQuota defined. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |

<details>
<summary>automount-token: 3 affected resources</summary>

- `kv-e2e-psa-baseline/Deployment/dangerous-caps-app`
- `kv-e2e-psa-baseline/Deployment/host-network-app`
- `kv-e2e-psa-baseline/Deployment/privileged-app`

</details>

<details>
<summary>default-service-account: 3 affected resources</summary>

- `kv-e2e-psa-baseline/Deployment/dangerous-caps-app`
- `kv-e2e-psa-baseline/Deployment/host-network-app`
- `kv-e2e-psa-baseline/Deployment/privileged-app`

</details>

<details>
<summary>privilege-escalation: 3 affected resources</summary>

- `kv-e2e-psa-baseline/Deployment/dangerous-caps-app (pause)`
- `kv-e2e-psa-baseline/Deployment/host-network-app (pause)`
- `kv-e2e-psa-baseline/Deployment/privileged-app (pause)`

</details>

<details>
<summary>psa-baseline-violations: 4 affected resources</summary>

- `kv-e2e-psa-baseline/Deployment/dangerous-caps-app (pause)`
- `kv-e2e-psa-baseline/Deployment/host-network-app`
- `kv-e2e-psa-baseline/Deployment/privileged-app`
- `kv-e2e-psa-baseline/Deployment/privileged-app (pause)`

</details>

<details>
<summary>run-as-root: 3 affected resources</summary>

- `kv-e2e-psa-baseline/Deployment/dangerous-caps-app (pause)`
- `kv-e2e-psa-baseline/Deployment/host-network-app (pause)`
- `kv-e2e-psa-baseline/Deployment/privileged-app (pause)`

</details>

<details>
<summary>apparmor-profile: 3 affected resources</summary>

- `kv-e2e-psa-baseline/Deployment/dangerous-caps-app (pause)`
- `kv-e2e-psa-baseline/Deployment/host-network-app (pause)`
- `kv-e2e-psa-baseline/Deployment/privileged-app (pause)`

</details>

<details>
<summary>capabilities-not-dropped: 3 affected resources</summary>

- `kv-e2e-psa-baseline/Deployment/dangerous-caps-app (pause)`
- `kv-e2e-psa-baseline/Deployment/host-network-app (pause)`
- `kv-e2e-psa-baseline/Deployment/privileged-app (pause)`

</details>

<details>
<summary>image-pull-policy: 3 affected resources</summary>

- `kv-e2e-psa-baseline/Deployment/dangerous-caps-app (pause)`
- `kv-e2e-psa-baseline/Deployment/host-network-app (pause)`
- `kv-e2e-psa-baseline/Deployment/privileged-app (pause)`

</details>

<details>
<summary>psa-restricted-violations: 9 affected resources</summary>

- `kv-e2e-psa-baseline/Deployment/dangerous-caps-app (pause)`
- `kv-e2e-psa-baseline/Deployment/dangerous-caps-app (pause)`
- `kv-e2e-psa-baseline/Deployment/dangerous-caps-app (pause)`
- `kv-e2e-psa-baseline/Deployment/host-network-app (pause)`
- `kv-e2e-psa-baseline/Deployment/host-network-app (pause)`
- `kv-e2e-psa-baseline/Deployment/host-network-app (pause)`
- `kv-e2e-psa-baseline/Deployment/privileged-app (pause)`
- `kv-e2e-psa-baseline/Deployment/privileged-app (pause)`
- `kv-e2e-psa-baseline/Deployment/privileged-app (pause)`

</details>

<details>
<summary>read-only-rootfs: 3 affected resources</summary>

- `kv-e2e-psa-baseline/Deployment/dangerous-caps-app (pause)`
- `kv-e2e-psa-baseline/Deployment/host-network-app (pause)`
- `kv-e2e-psa-baseline/Deployment/privileged-app (pause)`

</details>

<details>
<summary>resource-limits-missing: 3 affected resources</summary>

- `kv-e2e-psa-baseline/Deployment/dangerous-caps-app (pause)`
- `kv-e2e-psa-baseline/Deployment/host-network-app (pause)`
- `kv-e2e-psa-baseline/Deployment/privileged-app (pause)`

</details>

<details>
<summary>resource-requests-missing: 3 affected resources</summary>

- `kv-e2e-psa-baseline/Deployment/dangerous-caps-app (pause)`
- `kv-e2e-psa-baseline/Deployment/host-network-app (pause)`
- `kv-e2e-psa-baseline/Deployment/privileged-app (pause)`

</details>

<details>
<summary>run-as-group: 3 affected resources</summary>

- `kv-e2e-psa-baseline/Deployment/dangerous-caps-app (pause)`
- `kv-e2e-psa-baseline/Deployment/host-network-app (pause)`
- `kv-e2e-psa-baseline/Deployment/privileged-app (pause)`

</details>

<details>
<summary>seccomp-profile: 3 affected resources</summary>

- `kv-e2e-psa-baseline/Deployment/dangerous-caps-app (pause)`
- `kv-e2e-psa-baseline/Deployment/host-network-app (pause)`
- `kv-e2e-psa-baseline/Deployment/privileged-app (pause)`

</details>

<details>
<summary>token-projection-config: 3 affected resources</summary>

- `kv-e2e-psa-baseline/Deployment/dangerous-caps-app`
- `kv-e2e-psa-baseline/Deployment/host-network-app`
- `kv-e2e-psa-baseline/Deployment/privileged-app`

</details>

<details>
<summary>ephemeral-storage-limits: 3 affected resources</summary>

- `kv-e2e-psa-baseline/Deployment/dangerous-caps-app (pause)`
- `kv-e2e-psa-baseline/Deployment/host-network-app (pause)`
- `kv-e2e-psa-baseline/Deployment/privileged-app (pause)`

</details>

<details>
<summary>image-no-digest: 3 affected resources</summary>

- `kv-e2e-psa-baseline/Deployment/dangerous-caps-app (pause)`
- `kv-e2e-psa-baseline/Deployment/host-network-app (pause)`
- `kv-e2e-psa-baseline/Deployment/privileged-app (pause)`

</details>

<details>
<summary>liveness-readiness-probes: 6 affected resources</summary>

- `kv-e2e-psa-baseline/Deployment/dangerous-caps-app (pause)`
- `kv-e2e-psa-baseline/Deployment/dangerous-caps-app (pause)`
- `kv-e2e-psa-baseline/Deployment/host-network-app (pause)`
- `kv-e2e-psa-baseline/Deployment/host-network-app (pause)`
- `kv-e2e-psa-baseline/Deployment/privileged-app (pause)`
- `kv-e2e-psa-baseline/Deployment/privileged-app (pause)`

</details>

<details>
<summary>priority-class-missing: 3 affected resources</summary>

- `kv-e2e-psa-baseline/Deployment/dangerous-caps-app`
- `kv-e2e-psa-baseline/Deployment/host-network-app`
- `kv-e2e-psa-baseline/Deployment/privileged-app`

</details>

<details>
<summary>runtime-class: 3 affected resources</summary>

- `kv-e2e-psa-baseline/Deployment/dangerous-caps-app`
- `kv-e2e-psa-baseline/Deployment/host-network-app`
- `kv-e2e-psa-baseline/Deployment/privileged-app`

</details>

<details>
<summary>topology-spread: 3 affected resources</summary>

- `kv-e2e-psa-baseline/Deployment/dangerous-caps-app`
- `kv-e2e-psa-baseline/Deployment/host-network-app`
- `kv-e2e-psa-baseline/Deployment/privileged-app`

</details>

<details>
<summary>Remediation: host-network (1 resources affected)</summary>

## Why This Matters

Containers with hostNetwork bypass Kubernetes NetworkPolicies entirely and gain access to all network interfaces on the node, including the node's IP address and loopback. An attacker can use this to sniff traffic from other pods, access node-local services such as the kubelet API on port 10250, or impersonate the node on the network.

## How to Fix

Disable host networking in the pod spec and use Kubernetes Services for exposure:

```yaml
spec:
  hostNetwork: false
```

Use ClusterIP Services, NodePort, LoadBalancer, or Ingress resources to expose your application. Only CNI plugins, kube-proxy, and certain monitoring agents legitimately need host networking.

## Learn More

This aligns with CIS Benchmark 5.2.4 and the Pod Security Standards "Baseline" profile. Network namespace isolation is essential for NetworkPolicy enforcement and cluster network segmentation.

**Affected resources:** kv-e2e-psa-baseline/Deployment/host-network-app

</details>

<details>
<summary>Remediation: host-pid (1 resources affected)</summary>

## Why This Matters

When hostPID is enabled, containers share the host's process ID namespace and can see every process running on the node, including processes from other pods and system daemons. An attacker can use this to inspect environment variables containing secrets, send signals to critical processes, or exploit /proc entries to escape the container entirely.

## How to Fix

Disable host PID namespace sharing in the pod spec:

```yaml
spec:
  hostPID: false
```

If you need process visibility for monitoring or debugging, consider using ephemeral containers or a dedicated monitoring DaemonSet with tightly scoped RBAC instead.

## Learn More

This check aligns with CIS Benchmark 5.2.2 and the Pod Security Standards "Baseline" profile, which prohibits hostPID. Process namespace isolation is a fundamental container security boundary.

**Affected resources:** kv-e2e-psa-baseline/Deployment/privileged-app

</details>

<details>
<summary>Remediation: privileged (1 resources affected)</summary>

## Why This Matters

A privileged container runs with all Linux capabilities and has direct access to the host's devices, filesystems, and kernel. An attacker who compromises a privileged container can immediately escape to the host node, access secrets from other pods, and pivot across the entire cluster. This is the single most dangerous workload misconfiguration.

## How to Fix

Set `privileged` to `false` in the container's securityContext:

```yaml
securityContext:
  privileged: false
  allowPrivilegeEscalation: false
  capabilities:
    drop: ["ALL"]
```

If your container requires specific host access (e.g., network configuration), grant only the individual capabilities it needs via `capabilities.add` instead of enabling full privileged mode.

## Learn More

This check aligns with CIS Kubernetes Benchmark 5.2.1 and the Pod Security Standards "Baseline" profile, which both prohibit privileged containers. See the Kubernetes documentation on Pod Security Standards for details.

**Affected resources:** kv-e2e-psa-baseline/Deployment/privileged-app

</details>

<details>
<summary>Remediation: automount-token (3 resources affected)</summary>

## Why This Matters

When a ServiceAccount token is auto-mounted, every container in the pod can call the Kubernetes API. If a container is compromised through a vulnerability or misconfiguration, the attacker gains API access to enumerate resources, read secrets, or escalate privileges.

## How to Fix

Disable auto-mounting at the pod spec level for workloads that do not need API access:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      automountServiceAccountToken: false
      containers:
        - name: app
          image: my-app:latest
```

For workloads that do require API access, use projected tokens with bounded lifetime and audience restrictions instead of the default long-lived token.

## Learn More

Refer to the Kubernetes documentation on configuring service accounts for pods and CIS Kubernetes Benchmark 5.1.6 for auto-mount token guidance.

**Affected resources:** kv-e2e-psa-baseline/Deployment/dangerous-caps-app, kv-e2e-psa-baseline/Deployment/host-network-app, kv-e2e-psa-baseline/Deployment/privileged-app

</details>

<details>
<summary>Remediation: capabilities-added (1 resources affected)</summary>

## Why This Matters

Linux capabilities like SYS_ADMIN, NET_RAW, and SYS_PTRACE grant kernel-level powers that dramatically expand a container's attack surface. SYS_ADMIN alone enables filesystem mounts and namespace manipulation that can lead to container escape. NET_RAW allows ARP spoofing and network sniffing attacks within the cluster.

## How to Fix

Drop all capabilities and only add back the specific ones your application truly requires:

```yaml
securityContext:
  capabilities:
    drop: ["ALL"]
    add: []  # Only add specific caps after careful review
```

If your application needs to bind to ports below 1024, consider using a Kubernetes Service instead of granting NET_BIND_SERVICE. If setup tasks need elevated permissions, use an init container.

## Learn More

The Pod Security Standards "Restricted" profile only allows NET_BIND_SERVICE. Refer to the Linux capabilities man page (capabilities(7)) and CIS Benchmark 5.2.7-5.2.9 for guidance on acceptable capabilities.

**Affected resources:** kv-e2e-psa-baseline/Deployment/dangerous-caps-app

</details>

<details>
<summary>Remediation: default-service-account (3 resources affected)</summary>

## Why This Matters

The default ServiceAccount is shared by every pod in a namespace. If any pod is compromised, the attacker inherits whatever permissions have been granted to the default account via role bindings, enabling lateral movement across all workloads sharing it.

## How to Fix

Create a dedicated ServiceAccount for each workload and reference it in the pod spec:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-app
  namespace: production
automountServiceAccountToken: false
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      serviceAccountName: my-app
```

Grant only the permissions the workload actually needs via a dedicated Role and RoleBinding.

## Learn More

See the Kubernetes documentation on managing service accounts and CIS Kubernetes Benchmark 5.1.5 for guidance on ensuring default service accounts are not actively used.

**Affected resources:** kv-e2e-psa-baseline/Deployment/dangerous-caps-app, kv-e2e-psa-baseline/Deployment/host-network-app, kv-e2e-psa-baseline/Deployment/privileged-app

</details>

<details>
<summary>Remediation: privilege-escalation (3 resources affected)</summary>

## Why This Matters

By default, Kubernetes allows containers to escalate privileges via setuid/setgid binaries, which let a process gain more permissions than its parent. An attacker can exploit this using setuid binaries already present in the container image (like `su`, `sudo`, or `ping`) to elevate from a low-privilege user to root.

## How to Fix

Explicitly disable privilege escalation in the container's securityContext:

```yaml
securityContext:
  allowPrivilegeEscalation: false
  runAsNonRoot: true
  capabilities:
    drop: ["ALL"]
```

This blocks the use of setuid/setgid binaries and prevents the no_new_privs Linux flag from being cleared. The vast majority of application containers do not need privilege escalation.

## Learn More

This is required by the Pod Security Standards "Restricted" profile and CIS Benchmark 5.2.5. Disabling privilege escalation is one of the most impactful single-line security improvements you can make.

**Affected resources:** kv-e2e-psa-baseline/Deployment/dangerous-caps-app, kv-e2e-psa-baseline/Deployment/host-network-app, kv-e2e-psa-baseline/Deployment/privileged-app

</details>

<details>
<summary>Remediation: psa-baseline-violations (4 resources affected)</summary>

## Why This Matters

Adding ALL or SYS_ADMIN capabilities grants the container near-root privileges on the host. SYS_ADMIN alone enables mounting filesystems, loading kernel modules, and other operations that can lead to full container escape.

## How to Fix

Drop all capabilities and add back only the specific ones your application requires:

```yaml
securityContext:
  capabilities:
    drop: [ALL]
    add: [NET_BIND_SERVICE]  # Only what is truly needed
```

Test your application with all capabilities dropped first, then add back only those that cause failures.

## Learn More

See the Pod Security Standards Baseline profile and the capabilities(7) man page for the full list of Linux capabilities. CIS Kubernetes Benchmark 5.2.7 recommends minimizing the set of added capabilities.

**Affected resources:** kv-e2e-psa-baseline/Deployment/dangerous-caps-app, kv-e2e-psa-baseline/Deployment/host-network-app, kv-e2e-psa-baseline/Deployment/privileged-app, kv-e2e-psa-baseline/Deployment/privileged-app

</details>

<details>
<summary>Remediation: run-as-root (3 resources affected)</summary>

## Why This Matters

Without `runAsNonRoot: true`, Kubernetes does not enforce non-root execution and the container may default to running as UID 0 depending on the image's USER directive. If the image defaults to root, the container process gains full privileges, increasing the blast radius of any compromise or container escape.

## How to Fix

Enforce non-root execution in the securityContext:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
```

With `runAsNonRoot: true`, Kubernetes will reject the pod at admission time if the container image attempts to run as root. Setting an explicit `runAsUser` provides an additional guarantee.

## Learn More

This aligns with CIS Benchmark 5.2.6 and the Pod Security Standards "Restricted" profile. The `runAsNonRoot` field acts as a safety net even when images change their default USER.

**Affected resources:** kv-e2e-psa-baseline/Deployment/dangerous-caps-app, kv-e2e-psa-baseline/Deployment/host-network-app, kv-e2e-psa-baseline/Deployment/privileged-app

</details>

<details>
<summary>Remediation: network-policy-missing (1 resources affected)</summary>

## Why This Matters

Without NetworkPolicies, every pod in this namespace can communicate freely with every other pod in the cluster. If an attacker compromises a single pod, they can move laterally to databases, internal APIs, and other sensitive services with no network-level barriers.

## How to Fix

Create a default-deny NetworkPolicy for the namespace, then add targeted allow rules for legitimate traffic:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: my-namespace
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
```

After applying the default-deny, create additional NetworkPolicy resources that whitelist only the specific ingress and egress flows your workloads require.

## Learn More

See the Kubernetes documentation on NetworkPolicies and CIS Kubernetes Benchmark 5.3.2. A CNI plugin that supports NetworkPolicy (Calico, Cilium, Weave Net) must be installed for policies to take effect.

**Affected resources:** kv-e2e-psa-baseline/Namespace/kv-e2e-psa-baseline

</details>

<details>
<summary>Remediation: apparmor-profile (3 resources affected)</summary>

## Why This Matters

AppArmor provides mandatory access control (MAC) that restricts which files, network resources, and capabilities a container process can access. Without an AppArmor profile, the container operates without these restrictions, allowing an attacker with code execution to access any file the container user can read and make unrestricted network connections.

## How to Fix

Apply an AppArmor profile in the container's securityContext (Kubernetes 1.30+):

```yaml
securityContext:
  appArmorProfile:
    type: RuntimeDefault
```

The RuntimeDefault profile provides sensible restrictions for most applications. For tighter control, create a custom Localhost profile that only allows the specific file and network access your application needs.

## Learn More

AppArmor is available on Debian/Ubuntu-based nodes. RHEL/CentOS nodes use SELinux instead. Both provide MAC enforcement. Refer to CIS Benchmark 5.7.5 and the Kubernetes AppArmor documentation.

**Affected resources:** kv-e2e-psa-baseline/Deployment/dangerous-caps-app, kv-e2e-psa-baseline/Deployment/host-network-app, kv-e2e-psa-baseline/Deployment/privileged-app

</details>

<details>
<summary>Remediation: capabilities-not-dropped (3 resources affected)</summary>

## Why This Matters

By default, containers receive a set of Linux capabilities including KILL, SETUID, SETGID, and NET_RAW. These defaults are rarely needed by application code and significantly increase the potential damage from a container compromise. Dropping all capabilities follows the principle of least privilege.

## How to Fix

Explicitly drop all capabilities and selectively add back only what your application needs:

```yaml
securityContext:
  capabilities:
    drop: ["ALL"]
    add: ["NET_BIND_SERVICE"]  # Only if needed
```

Most web applications, API servers, and background workers run perfectly with all capabilities dropped. Test your application after making this change to confirm no functionality is lost.

## Learn More

This is required by the Pod Security Standards "Restricted" profile and aligns with CIS Benchmark 5.2.7. Kubernetes best practice is to treat capability grants as exceptions that require explicit justification.

**Affected resources:** kv-e2e-psa-baseline/Deployment/dangerous-caps-app, kv-e2e-psa-baseline/Deployment/host-network-app, kv-e2e-psa-baseline/Deployment/privileged-app

</details>

<details>
<summary>Remediation: image-pull-policy (3 resources affected)</summary>

## Why This Matters

When a mutable image tag is used without `imagePullPolicy: Always`, Kubernetes may serve a cached version of the image from the node. If the tag has been updated in the registry (with a security patch or -- worse -- a compromised layer), the running container will not reflect those changes.

## How to Fix

Set `imagePullPolicy: Always` for any container using a mutable tag:

```yaml
containers:
  - name: app
    image: nginx:1.25.3
    imagePullPolicy: Always   # Forces fresh pull each time
```

Alternatively, pin images by digest (`image@sha256:...`), which makes the pull policy irrelevant because the content is immutable.

## Learn More

See the Kubernetes documentation on image pull policies and CIS Kubernetes Benchmark 5.4.2 for pull policy guidance.

**Affected resources:** kv-e2e-psa-baseline/Deployment/dangerous-caps-app, kv-e2e-psa-baseline/Deployment/host-network-app, kv-e2e-psa-baseline/Deployment/privileged-app

</details>

<details>
<summary>Remediation: psa-restricted-violations (9 resources affected)</summary>

## Why This Matters

Running as root inside a container means that any container escape vulnerability immediately grants root access on the host node. Even without an escape, root inside the container can modify sensitive files, install packages, and access capabilities that non-root users cannot.

## How to Fix

Set `runAsNonRoot: true` and specify a non-root user ID in the security context:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
```

Set this at the pod level to apply to all containers. Ensure your container image supports running as a non-root user (many official images do).

## Learn More

See the Pod Security Standards Restricted profile and CIS Kubernetes Benchmark 5.2.6. Running as non-root is a fundamental container security best practice.

**Affected resources:** kv-e2e-psa-baseline/Deployment/dangerous-caps-app, kv-e2e-psa-baseline/Deployment/dangerous-caps-app, kv-e2e-psa-baseline/Deployment/dangerous-caps-app, kv-e2e-psa-baseline/Deployment/host-network-app, kv-e2e-psa-baseline/Deployment/host-network-app, kv-e2e-psa-baseline/Deployment/host-network-app, kv-e2e-psa-baseline/Deployment/privileged-app, kv-e2e-psa-baseline/Deployment/privileged-app, kv-e2e-psa-baseline/Deployment/privileged-app

</details>

<details>
<summary>Remediation: read-only-rootfs (3 resources affected)</summary>

## Why This Matters

A writable root filesystem allows an attacker who gains code execution in your container to modify application binaries, install attack tools, plant backdoors, or persist malware across container restarts. Making the filesystem read-only eliminates an entire class of post-exploitation techniques.

## How to Fix

Enable a read-only root filesystem and mount writable volumes only where needed:

```yaml
securityContext:
  readOnlyRootFilesystem: true
volumeMounts:
  - name: tmp
    mountPath: /tmp
volumes:
  - name: tmp
    emptyDir: {}
```

Common paths that need write access include /tmp, /var/cache, and /var/run. Mount each as an emptyDir or tmpfs volume rather than making the entire filesystem writable.

## Learn More

This aligns with CIS Benchmark 5.2.4 and the defense-in-depth principle. Combined with dropping capabilities and running as non-root, a read-only filesystem forms a strong container hardening baseline.

**Affected resources:** kv-e2e-psa-baseline/Deployment/dangerous-caps-app, kv-e2e-psa-baseline/Deployment/host-network-app, kv-e2e-psa-baseline/Deployment/privileged-app

</details>

<details>
<summary>Remediation: resource-limits-missing (3 resources affected)</summary>

## Why This Matters

Without resource limits, a single container can consume all available CPU and memory on a node, starving other workloads and triggering cascading failures. An attacker who compromises an unlimited container can mount a denial-of-service attack against the entire node with a simple fork bomb or memory allocation loop.

## How to Fix

Set both CPU and memory limits based on your application's actual resource usage:

```yaml
resources:
  limits:
    cpu: 500m
    memory: 256Mi
  requests:
    cpu: 100m
    memory: 128Mi
```

Profile your application under load to determine appropriate values. Set limits to handle peak usage and requests to match steady-state consumption.

## Learn More

Use LimitRange objects to enforce default limits at the namespace level. Resource limits also determine the pod's QoS class: pods with equal requests and limits get Guaranteed QoS and are last to be evicted.

**Affected resources:** kv-e2e-psa-baseline/Deployment/dangerous-caps-app, kv-e2e-psa-baseline/Deployment/host-network-app, kv-e2e-psa-baseline/Deployment/privileged-app

</details>

<details>
<summary>Remediation: resource-requests-missing (3 resources affected)</summary>

## Why This Matters

Resource requests tell the Kubernetes scheduler how much CPU and memory your container needs. Without requests, the scheduler treats the pod as needing zero resources and may pack too many pods onto a single node. This leads to overcommitment, resource contention, throttling, and OOM kills under load.

## How to Fix

Set resource requests based on your application's steady-state usage:

```yaml
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 256Mi
```

Observe your application's actual resource consumption using `kubectl top` or a monitoring tool, then set requests to match the typical steady-state usage.

## Learn More

Resource requests determine the pod's QoS class and scheduling behavior. Pods with requests equal to limits receive Guaranteed QoS. Use Vertical Pod Autoscaler (VPA) to automatically recommend request values.

**Affected resources:** kv-e2e-psa-baseline/Deployment/dangerous-caps-app, kv-e2e-psa-baseline/Deployment/host-network-app, kv-e2e-psa-baseline/Deployment/privileged-app

</details>

<details>
<summary>Remediation: run-as-group (3 resources affected)</summary>

## Why This Matters

Without an explicit runAsGroup, the container process defaults to GID 0 (the root group). Files and sockets owned by the root group become accessible to the container, including potentially sensitive host files if volumes are mounted. This widens the attack surface unnecessarily.

## How to Fix

Set an explicit non-root group in the securityContext:

```yaml
securityContext:
  runAsGroup: 1000
  runAsUser: 1000
  runAsNonRoot: true
```

Ensure the container image's application files and directories are readable by the specified GID. You may need to adjust file ownership in your Dockerfile with `chown`.

## Learn More

This aligns with CIS Benchmark 5.2.6 and the Pod Security Standards "Restricted" profile. Always set runAsUser, runAsGroup, and runAsNonRoot together for comprehensive identity control.

**Affected resources:** kv-e2e-psa-baseline/Deployment/dangerous-caps-app, kv-e2e-psa-baseline/Deployment/host-network-app, kv-e2e-psa-baseline/Deployment/privileged-app

</details>

<details>
<summary>Remediation: seccomp-profile (3 resources affected)</summary>

## Why This Matters

Without a Seccomp profile, containers can invoke any of the 300+ Linux system calls, leaving the entire kernel attack surface exposed. Kernel vulnerabilities in obscure syscalls are a primary vector for container escapes. Seccomp filtering blocks dangerous syscalls that legitimate applications never use.

## How to Fix

Apply a Seccomp profile at the container or pod level:

```yaml
securityContext:
  seccompProfile:
    type: RuntimeDefault
```

The RuntimeDefault profile blocks approximately 50 dangerous syscalls while allowing normal application behavior. For stricter controls, use a custom Localhost profile tailored to your application's needs. Set the profile at the pod level to apply it to all containers.

## Learn More

Seccomp profiles are required by the Pod Security Standards "Restricted" profile and CIS Benchmark 5.7.2. Use tools like `strace` or the Security Profiles Operator to generate custom profiles for your workloads.

**Affected resources:** kv-e2e-psa-baseline/Deployment/dangerous-caps-app, kv-e2e-psa-baseline/Deployment/host-network-app, kv-e2e-psa-baseline/Deployment/privileged-app

</details>

<details>
<summary>Remediation: token-projection-config (3 resources affected)</summary>

## Why This Matters

Without explicit projection configuration, ServiceAccount tokens use Kubernetes defaults: no audience restriction and a long expiration. A stolen token remains valid for an extended period and can be used against any API server endpoint, widening the blast radius of a compromise.

## How to Fix

Add a projected volume with explicit expiration and audience:

```yaml
spec:
  volumes:
    - name: token
      projected:
        sources:
          - serviceAccountToken:
              expirationSeconds: 3600
              audience: my-api
              path: token
  containers:
    - name: app
      volumeMounts:
        - name: token
          mountPath: /var/run/secrets/tokens
          readOnly: true
```

Projected tokens auto-rotate before expiry and are rejected by endpoints outside the specified audience.

## Learn More

See the Kubernetes documentation on projected volumes and service account token volume projection for detailed configuration options.

**Affected resources:** kv-e2e-psa-baseline/Deployment/dangerous-caps-app, kv-e2e-psa-baseline/Deployment/host-network-app, kv-e2e-psa-baseline/Deployment/privileged-app

</details>

<details>
<summary>Remediation: network-policy-egress-unrestricted (1 resources affected)</summary>

## Why This Matters

Without any egress NetworkPolicy in this namespace, pods can freely send traffic to any destination including the public internet. A compromised pod can exfiltrate sensitive data, reach cloud metadata services (e.g., 169.254.169.254), or establish reverse shells to attacker-controlled servers.

## How to Fix

Create a NetworkPolicy with `Egress` in `policyTypes` to restrict outbound traffic. At minimum, allow DNS resolution:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-egress
  namespace: my-namespace
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector: {}
      ports:
        - port: 53
          protocol: UDP
```

Add additional egress rules for specific services your workloads need to reach.

## Learn More

See the Kubernetes NetworkPolicy documentation and CIS Kubernetes Benchmark 5.3.2. Egress controls are a key defense-in-depth measure recommended by the NSA/CISA Kubernetes Hardening Guide.

**Affected resources:** kv-e2e-psa-baseline/Namespace/kv-e2e-psa-baseline

</details>

<details>
<summary>Remediation: psa-labels-missing (1 resources affected)</summary>

## Why This Matters

Without PSA enforcement labels, any pod configuration is allowed in this namespace, including privileged containers, host namespace access, and root execution. This bypasses Kubernetes' built-in Pod Security Standards and leaves the namespace vulnerable to workloads that could compromise the node.

## How to Fix

Add Pod Security Admission labels to enforce a security profile on all pods in the namespace:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: kv-e2e-psa-baseline
  labels:
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

Start with `baseline` enforcement to block known privilege escalations, then upgrade to `restricted` after verifying all workloads are compliant.

## Learn More

See the Kubernetes Pod Security Admission documentation and CIS Kubernetes Benchmark 5.2. The three-tier approach (enforce, audit, warn) allows gradual adoption of stricter profiles.

**Affected resources:** kv-e2e-psa-baseline/Namespace/kv-e2e-psa-baseline

</details>

<details>
<summary>Remediation: psa-mode-audit-only (1 resources affected)</summary>

## Why This Matters

Audit and warn modes only log violations or show warnings to users -- they do not actually block non-compliant pods from being created. Without the `enforce` label, insecure workloads such as privileged containers or root-running pods can still be admitted to the namespace.

## How to Fix

Add the `enforce` label alongside the existing audit/warn labels to actively block non-compliant pods:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

Set `enforce` to `baseline` initially and review audit logs for `restricted` violations before upgrading the enforcement level.

## Learn More

See the Kubernetes Pod Security Admission documentation on modes (enforce, audit, warn). CIS Kubernetes Benchmark 5.2 recommends active enforcement of Pod Security Standards, not just auditing.

**Affected resources:** kv-e2e-psa-baseline/Namespace/kv-e2e-psa-baseline

</details>

<details>
<summary>Remediation: ephemeral-storage-limits (3 resources affected)</summary>

## Why This Matters

Ephemeral storage includes container logs, emptyDir volumes, and the writable container layer. Without limits, a single container can fill the node's root disk, triggering eviction of all pods on that node and potentially causing a cascading failure across your cluster. This is a common denial-of-service vector.

## How to Fix

Set ephemeral-storage limits alongside your CPU and memory limits:

```yaml
resources:
  limits:
    ephemeral-storage: 1Gi
  requests:
    ephemeral-storage: 500Mi
```

Estimate your application's disk usage from logs, temporary files, and cache data. If your application writes large temporary files, consider using a PersistentVolumeClaim instead of ephemeral storage.

## Learn More

The kubelet evicts pods that exceed their ephemeral-storage limit. Use LimitRange to set default ephemeral-storage limits at the namespace level to catch containers that omit this setting.

**Affected resources:** kv-e2e-psa-baseline/Deployment/dangerous-caps-app, kv-e2e-psa-baseline/Deployment/host-network-app, kv-e2e-psa-baseline/Deployment/privileged-app

</details>

<details>
<summary>Remediation: image-no-digest (3 resources affected)</summary>

## Why This Matters

Image tags are mutable pointers -- a registry administrator or attacker can re-push a different image under the same tag. Without a digest, you have no cryptographic guarantee that the image you deploy is the one you tested.

## How to Fix

Pin images by their SHA-256 content digest for a fully immutable reference:

```yaml
containers:
  - name: app
    image: nginx@sha256:a8281ce420348a01ea6e   # Immutable
```

Use `crane digest nginx:1.25.3` or `skopeo inspect` to resolve a tag to its digest during CI/CD, then commit the pinned reference.

## Learn More

SLSA Level 1+ and NIST SP 800-190 recommend digest pinning for container supply chain integrity. See the Kubernetes images documentation for details.

**Affected resources:** kv-e2e-psa-baseline/Deployment/dangerous-caps-app, kv-e2e-psa-baseline/Deployment/host-network-app, kv-e2e-psa-baseline/Deployment/privileged-app

</details>

<details>
<summary>Remediation: liveness-readiness-probes (6 resources affected)</summary>

## Why This Matters

Without a liveness probe, Kubernetes cannot detect when a container has become unresponsive or deadlocked. The container continues running and consuming resources while failing to serve traffic. Users experience timeouts and errors until someone manually intervenes.

## How to Fix

Add a liveness probe that checks the container's health:

```yaml
containers:
  - name: app
    livenessProbe:
      httpGet:
        path: /healthz
        port: 8080
      initialDelaySeconds: 15
      periodSeconds: 10
      failureThreshold: 3
```

Use `httpGet` for HTTP services, `tcpSocket` for TCP services, or `exec` with a custom health check script for non-network workloads.

## Learn More

See the Kubernetes documentation on container probes. Set initialDelaySeconds high enough for your application to start, and consider adding a startupProbe for slow-starting containers.

**Affected resources:** kv-e2e-psa-baseline/Deployment/dangerous-caps-app, kv-e2e-psa-baseline/Deployment/dangerous-caps-app, kv-e2e-psa-baseline/Deployment/host-network-app, kv-e2e-psa-baseline/Deployment/host-network-app, kv-e2e-psa-baseline/Deployment/privileged-app, kv-e2e-psa-baseline/Deployment/privileged-app

</details>

<details>
<summary>Remediation: priority-class-missing (3 resources affected)</summary>

## Why This Matters

Without a PriorityClass, pods receive default priority (typically 0) and are among the first to be evicted during resource pressure or node maintenance. This means important application workloads may be killed before less critical ones, leading to unpredictable outages.

## How to Fix

Define PriorityClasses for your workloads and assign them appropriately:

```yaml
apiVersion: scheduling.k8s.io/v1
kind: PriorityClass
metadata:
  name: app-medium
value: 100000
---
# Reference in your workload:
spec:
  priorityClassName: app-medium
```

Create a tiered priority scheme (e.g., app-critical: 500000, app-medium: 100000, app-low: 10000) that reflects your workload importance hierarchy.

## Learn More

Refer to the Kubernetes Pod Priority and Preemption documentation. Establishing a consistent priority scheme across namespaces ensures predictable eviction behavior during resource contention.

**Affected resources:** kv-e2e-psa-baseline/Deployment/dangerous-caps-app, kv-e2e-psa-baseline/Deployment/host-network-app, kv-e2e-psa-baseline/Deployment/privileged-app

</details>

<details>
<summary>Remediation: runtime-class (3 resources affected)</summary>

## Why This Matters

Without a RuntimeClass, pods use the default container runtime (typically runc), which shares the host kernel directly with containers. A kernel vulnerability can allow container escape to the host. Sandboxed runtimes like gVisor or Kata Containers add an additional isolation layer that intercepts system calls or runs containers in lightweight VMs.

## How to Fix

Specify a sandboxed RuntimeClass in the pod spec:

```yaml
spec:
  runtimeClassName: gvisor
```

Available RuntimeClasses depend on your cluster configuration. Common options include `gvisor` (user-space kernel), `kata` (micro-VMs), and `firecracker`. Check your cluster's available RuntimeClasses with `kubectl get runtimeclasses`.

## Learn More

Sandboxed runtimes are especially important for multi-tenant clusters and workloads processing untrusted input. They add latency overhead, so evaluate performance requirements. See the Kubernetes RuntimeClass documentation.

**Affected resources:** kv-e2e-psa-baseline/Deployment/dangerous-caps-app, kv-e2e-psa-baseline/Deployment/host-network-app, kv-e2e-psa-baseline/Deployment/privileged-app

</details>

<details>
<summary>Remediation: topology-spread (3 resources affected)</summary>

## Why This Matters

Without topology spread constraints, the scheduler may place all replicas on the same node or in the same availability zone. If that node or zone fails, your entire service goes down despite having multiple replicas. This negates the high-availability benefits of running multiple pods.

## How to Fix

Add topology spread constraints to distribute replicas across failure domains:

```yaml
spec:
  topologySpreadConstraints:
    - maxSkew: 1
      topologyKey: kubernetes.io/hostname
      whenUnsatisfiable: DoNotSchedule
      labelSelector:
        matchLabels:
          app: my-app
    - maxSkew: 1
      topologyKey: topology.kubernetes.io/zone
      whenUnsatisfiable: ScheduleAnyway
```

Use `kubernetes.io/hostname` for node-level spreading and `topology.kubernetes.io/zone` for zone-level spreading.

## Learn More

See the Kubernetes Pod Topology Spread Constraints documentation. Combining hostname and zone constraints provides both node-level and zone-level fault tolerance.

**Affected resources:** kv-e2e-psa-baseline/Deployment/dangerous-caps-app, kv-e2e-psa-baseline/Deployment/host-network-app, kv-e2e-psa-baseline/Deployment/privileged-app

</details>

<details>
<summary>Remediation: limit-range-missing (1 resources affected)</summary>

## Why This Matters

Without a LimitRange, any container can be created without resource constraints. A single runaway or malicious pod can consume all node CPU and memory, causing denial of service for other workloads on the same node.

## How to Fix

Create a LimitRange in the namespace to set default and maximum resource constraints:

```yaml
apiVersion: v1
kind: LimitRange
metadata:
  name: default-limits
  namespace: my-app
spec:
  limits:
    - type: Container
      default:
        cpu: 500m
        memory: 256Mi
      defaultRequest:
        cpu: 100m
        memory: 128Mi
      max:
        cpu: "2"
        memory: 1Gi
```

Containers that omit resource requests/limits will inherit these defaults automatically.

## Learn More

CIS Kubernetes Benchmark 5.2.1 recommends LimitRanges for resource governance. See https://kubernetes.io/docs/concepts/policy/limit-range/ for configuration details.

**Affected resources:** kv-e2e-psa-baseline/Namespace/kv-e2e-psa-baseline

</details>

<details>
<summary>Remediation: resource-quota-missing (1 resources affected)</summary>

## Why This Matters

Without a ResourceQuota, a single namespace can consume the entire cluster's CPU, memory, and storage. This creates a noisy-neighbor problem where one team's workloads starve others, and makes capacity planning impossible.

## How to Fix

Create a ResourceQuota to cap the namespace's total resource consumption:

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: compute-quota
  namespace: my-app
spec:
  hard:
    requests.cpu: "10"
    requests.memory: 20Gi
    limits.cpu: "20"
    limits.memory: 40Gi
    pods: "50"
    services: "10"
```

Tune quota values based on the namespace's actual workload requirements and cluster capacity.

## Learn More

CIS Kubernetes Benchmark 5.2.2 recommends ResourceQuotas for multi-tenant clusters. See https://kubernetes.io/docs/concepts/policy/resource-quotas/ for quota configuration and enforcement behavior.

**Affected resources:** kv-e2e-psa-baseline/Namespace/kv-e2e-psa-baseline

</details>

### kv-e2e-psa-pinned (21 findings — 🟠3 🟡6 🔵12)

| Severity | Check | Resources | Message | Frameworks |
|----------|-------|-----------|---------|-----------|
| 🟠 High | automount-token | kv-e2e-psa-pinned/Deployment/compliant-app | Deployment "compliant-app" auto-mounts a ServiceAccount token. Most workloads do not need Kubernetes API access. | CIS 5.1.6 · MITRE T1552.007 · NSA 3.2 |
| 🟠 High | default-service-account | kv-e2e-psa-pinned/Deployment/compliant-app | Deployment "compliant-app" uses the default ServiceAccount, which may have unintended permissions. | CIS 5.1.5 · CIS 5.1.6 · MITRE T1078.001 · NSA 3.1 · NSA 3.2 |
| 🟠 High | network-policy-missing | kv-e2e-psa-pinned/Namespace/kv-e2e-psa-pinned | Namespace "kv-e2e-psa-pinned" has no NetworkPolicy defined. All pods are unrestricted. | CIS 5.3.2 · MITRE T1046 · NSA 4.1 · NSA 4.2 |
| 🟡 Medium | apparmor-profile | kv-e2e-psa-pinned/Deployment/compliant-app (pause) | Container "pause" does not have an AppArmor profile set. | CIS 5.6.3 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | image-pull-policy | kv-e2e-psa-pinned/Deployment/compliant-app (pause) | Container "pause" uses a mutable image tag with pullPolicy "IfNotPresent" (image: registry.k8s.io/pause:3.9), risking stale images. | CIS 5.5.1 · MITRE T1525 · NSA 1.4 |
| 🟡 Medium | resource-limits-missing | kv-e2e-psa-pinned/Deployment/compliant-app (pause) | Container "pause" is missing both CPU and memory limits. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🟡 Medium | resource-requests-missing | kv-e2e-psa-pinned/Deployment/compliant-app (pause) | Container "pause" is missing both CPU and memory requests. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🟡 Medium | token-projection-config | kv-e2e-psa-pinned/Deployment/compliant-app | Deployment "compliant-app" does not use explicitly configured projected ServiceAccount tokens with expiry and audience restrictions. | CIS 5.1.6 · MITRE T1552.007 · NSA 3.2 |
| 🟡 Medium | network-policy-egress-unrestricted | kv-e2e-psa-pinned/Namespace/kv-e2e-psa-pinned | Namespace "kv-e2e-psa-pinned" has no NetworkPolicy with egress restrictions. Pods can reach any external destination. | CIS 5.3.2 · MITRE T1048 · NSA 4.2 |
| 🔵 Low | ephemeral-storage-limits | kv-e2e-psa-pinned/Deployment/compliant-app (pause) | Container "pause" is missing ephemeral-storage limits. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | image-no-digest | kv-e2e-psa-pinned/Deployment/compliant-app (pause) | Container "pause" image is not pinned by digest (image: registry.k8s.io/pause:3.9), allowing tag mutation. | CIS 5.5.1 · MITRE T1525 · NSA 1.4 |
| 🔵 Low | liveness-readiness-probes | **2 resources** | Container "pause" has no liveness probe configured. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | priority-class-missing | kv-e2e-psa-pinned/Deployment/compliant-app | Deployment "compliant-app" has no PriorityClass set; it will be evicted first during resource pressure. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | runtime-class | kv-e2e-psa-pinned/Deployment/compliant-app | Pod "compliant-app" does not specify a RuntimeClass, using the default (unsandboxed) runtime. | CIS 5.6.3 · MITRE T1611 · NSA 2.1 |
| 🔵 Low | topology-spread | kv-e2e-psa-pinned/Deployment/compliant-app | Deployment "compliant-app" has no topology spread constraints; all replicas may be scheduled on the same node. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | limit-range-missing | kv-e2e-psa-pinned/Namespace/kv-e2e-psa-pinned | Namespace "kv-e2e-psa-pinned" has no LimitRange defined. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | psa-version-pinning | **3 resources** | Namespace "kv-e2e-psa-pinned" has PSA version label pod-security.kubernetes.io/enforce-version pinned to "v1.25" instead of "latest"; new restrictions won't apply on upgrade. | CIS 5.2.1 · MITRE T1610 · NSA 2.1 |
| 🔵 Low | resource-quota-missing | kv-e2e-psa-pinned/Namespace/kv-e2e-psa-pinned | Namespace "kv-e2e-psa-pinned" has no ResourceQuota defined. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |

<details>
<summary>liveness-readiness-probes: 2 affected resources</summary>

- `kv-e2e-psa-pinned/Deployment/compliant-app (pause)`
- `kv-e2e-psa-pinned/Deployment/compliant-app (pause)`

</details>

<details>
<summary>psa-version-pinning: 3 affected resources</summary>

- `kv-e2e-psa-pinned/Namespace/kv-e2e-psa-pinned`
- `kv-e2e-psa-pinned/Namespace/kv-e2e-psa-pinned`
- `kv-e2e-psa-pinned/Namespace/kv-e2e-psa-pinned`

</details>

<details>
<summary>Remediation: automount-token (1 resources affected)</summary>

## Why This Matters

When a ServiceAccount token is auto-mounted, every container in the pod can call the Kubernetes API. If a container is compromised through a vulnerability or misconfiguration, the attacker gains API access to enumerate resources, read secrets, or escalate privileges.

## How to Fix

Disable auto-mounting at the pod spec level for workloads that do not need API access:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      automountServiceAccountToken: false
      containers:
        - name: app
          image: my-app:latest
```

For workloads that do require API access, use projected tokens with bounded lifetime and audience restrictions instead of the default long-lived token.

## Learn More

Refer to the Kubernetes documentation on configuring service accounts for pods and CIS Kubernetes Benchmark 5.1.6 for auto-mount token guidance.

**Affected resources:** kv-e2e-psa-pinned/Deployment/compliant-app

</details>

<details>
<summary>Remediation: default-service-account (1 resources affected)</summary>

## Why This Matters

The default ServiceAccount is shared by every pod in a namespace. If any pod is compromised, the attacker inherits whatever permissions have been granted to the default account via role bindings, enabling lateral movement across all workloads sharing it.

## How to Fix

Create a dedicated ServiceAccount for each workload and reference it in the pod spec:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-app
  namespace: production
automountServiceAccountToken: false
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      serviceAccountName: my-app
```

Grant only the permissions the workload actually needs via a dedicated Role and RoleBinding.

## Learn More

See the Kubernetes documentation on managing service accounts and CIS Kubernetes Benchmark 5.1.5 for guidance on ensuring default service accounts are not actively used.

**Affected resources:** kv-e2e-psa-pinned/Deployment/compliant-app

</details>

<details>
<summary>Remediation: network-policy-missing (1 resources affected)</summary>

## Why This Matters

Without NetworkPolicies, every pod in this namespace can communicate freely with every other pod in the cluster. If an attacker compromises a single pod, they can move laterally to databases, internal APIs, and other sensitive services with no network-level barriers.

## How to Fix

Create a default-deny NetworkPolicy for the namespace, then add targeted allow rules for legitimate traffic:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: my-namespace
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
```

After applying the default-deny, create additional NetworkPolicy resources that whitelist only the specific ingress and egress flows your workloads require.

## Learn More

See the Kubernetes documentation on NetworkPolicies and CIS Kubernetes Benchmark 5.3.2. A CNI plugin that supports NetworkPolicy (Calico, Cilium, Weave Net) must be installed for policies to take effect.

**Affected resources:** kv-e2e-psa-pinned/Namespace/kv-e2e-psa-pinned

</details>

<details>
<summary>Remediation: apparmor-profile (1 resources affected)</summary>

## Why This Matters

AppArmor provides mandatory access control (MAC) that restricts which files, network resources, and capabilities a container process can access. Without an AppArmor profile, the container operates without these restrictions, allowing an attacker with code execution to access any file the container user can read and make unrestricted network connections.

## How to Fix

Apply an AppArmor profile in the container's securityContext (Kubernetes 1.30+):

```yaml
securityContext:
  appArmorProfile:
    type: RuntimeDefault
```

The RuntimeDefault profile provides sensible restrictions for most applications. For tighter control, create a custom Localhost profile that only allows the specific file and network access your application needs.

## Learn More

AppArmor is available on Debian/Ubuntu-based nodes. RHEL/CentOS nodes use SELinux instead. Both provide MAC enforcement. Refer to CIS Benchmark 5.7.5 and the Kubernetes AppArmor documentation.

**Affected resources:** kv-e2e-psa-pinned/Deployment/compliant-app

</details>

<details>
<summary>Remediation: image-pull-policy (1 resources affected)</summary>

## Why This Matters

When a mutable image tag is used without `imagePullPolicy: Always`, Kubernetes may serve a cached version of the image from the node. If the tag has been updated in the registry (with a security patch or -- worse -- a compromised layer), the running container will not reflect those changes.

## How to Fix

Set `imagePullPolicy: Always` for any container using a mutable tag:

```yaml
containers:
  - name: app
    image: nginx:1.25.3
    imagePullPolicy: Always   # Forces fresh pull each time
```

Alternatively, pin images by digest (`image@sha256:...`), which makes the pull policy irrelevant because the content is immutable.

## Learn More

See the Kubernetes documentation on image pull policies and CIS Kubernetes Benchmark 5.4.2 for pull policy guidance.

**Affected resources:** kv-e2e-psa-pinned/Deployment/compliant-app

</details>

<details>
<summary>Remediation: resource-limits-missing (1 resources affected)</summary>

## Why This Matters

Without resource limits, a single container can consume all available CPU and memory on a node, starving other workloads and triggering cascading failures. An attacker who compromises an unlimited container can mount a denial-of-service attack against the entire node with a simple fork bomb or memory allocation loop.

## How to Fix

Set both CPU and memory limits based on your application's actual resource usage:

```yaml
resources:
  limits:
    cpu: 500m
    memory: 256Mi
  requests:
    cpu: 100m
    memory: 128Mi
```

Profile your application under load to determine appropriate values. Set limits to handle peak usage and requests to match steady-state consumption.

## Learn More

Use LimitRange objects to enforce default limits at the namespace level. Resource limits also determine the pod's QoS class: pods with equal requests and limits get Guaranteed QoS and are last to be evicted.

**Affected resources:** kv-e2e-psa-pinned/Deployment/compliant-app

</details>

<details>
<summary>Remediation: resource-requests-missing (1 resources affected)</summary>

## Why This Matters

Resource requests tell the Kubernetes scheduler how much CPU and memory your container needs. Without requests, the scheduler treats the pod as needing zero resources and may pack too many pods onto a single node. This leads to overcommitment, resource contention, throttling, and OOM kills under load.

## How to Fix

Set resource requests based on your application's steady-state usage:

```yaml
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 256Mi
```

Observe your application's actual resource consumption using `kubectl top` or a monitoring tool, then set requests to match the typical steady-state usage.

## Learn More

Resource requests determine the pod's QoS class and scheduling behavior. Pods with requests equal to limits receive Guaranteed QoS. Use Vertical Pod Autoscaler (VPA) to automatically recommend request values.

**Affected resources:** kv-e2e-psa-pinned/Deployment/compliant-app

</details>

<details>
<summary>Remediation: token-projection-config (1 resources affected)</summary>

## Why This Matters

Without explicit projection configuration, ServiceAccount tokens use Kubernetes defaults: no audience restriction and a long expiration. A stolen token remains valid for an extended period and can be used against any API server endpoint, widening the blast radius of a compromise.

## How to Fix

Add a projected volume with explicit expiration and audience:

```yaml
spec:
  volumes:
    - name: token
      projected:
        sources:
          - serviceAccountToken:
              expirationSeconds: 3600
              audience: my-api
              path: token
  containers:
    - name: app
      volumeMounts:
        - name: token
          mountPath: /var/run/secrets/tokens
          readOnly: true
```

Projected tokens auto-rotate before expiry and are rejected by endpoints outside the specified audience.

## Learn More

See the Kubernetes documentation on projected volumes and service account token volume projection for detailed configuration options.

**Affected resources:** kv-e2e-psa-pinned/Deployment/compliant-app

</details>

<details>
<summary>Remediation: network-policy-egress-unrestricted (1 resources affected)</summary>

## Why This Matters

Without any egress NetworkPolicy in this namespace, pods can freely send traffic to any destination including the public internet. A compromised pod can exfiltrate sensitive data, reach cloud metadata services (e.g., 169.254.169.254), or establish reverse shells to attacker-controlled servers.

## How to Fix

Create a NetworkPolicy with `Egress` in `policyTypes` to restrict outbound traffic. At minimum, allow DNS resolution:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-egress
  namespace: my-namespace
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector: {}
      ports:
        - port: 53
          protocol: UDP
```

Add additional egress rules for specific services your workloads need to reach.

## Learn More

See the Kubernetes NetworkPolicy documentation and CIS Kubernetes Benchmark 5.3.2. Egress controls are a key defense-in-depth measure recommended by the NSA/CISA Kubernetes Hardening Guide.

**Affected resources:** kv-e2e-psa-pinned/Namespace/kv-e2e-psa-pinned

</details>

<details>
<summary>Remediation: ephemeral-storage-limits (1 resources affected)</summary>

## Why This Matters

Ephemeral storage includes container logs, emptyDir volumes, and the writable container layer. Without limits, a single container can fill the node's root disk, triggering eviction of all pods on that node and potentially causing a cascading failure across your cluster. This is a common denial-of-service vector.

## How to Fix

Set ephemeral-storage limits alongside your CPU and memory limits:

```yaml
resources:
  limits:
    ephemeral-storage: 1Gi
  requests:
    ephemeral-storage: 500Mi
```

Estimate your application's disk usage from logs, temporary files, and cache data. If your application writes large temporary files, consider using a PersistentVolumeClaim instead of ephemeral storage.

## Learn More

The kubelet evicts pods that exceed their ephemeral-storage limit. Use LimitRange to set default ephemeral-storage limits at the namespace level to catch containers that omit this setting.

**Affected resources:** kv-e2e-psa-pinned/Deployment/compliant-app

</details>

<details>
<summary>Remediation: image-no-digest (1 resources affected)</summary>

## Why This Matters

Image tags are mutable pointers -- a registry administrator or attacker can re-push a different image under the same tag. Without a digest, you have no cryptographic guarantee that the image you deploy is the one you tested.

## How to Fix

Pin images by their SHA-256 content digest for a fully immutable reference:

```yaml
containers:
  - name: app
    image: nginx@sha256:a8281ce420348a01ea6e   # Immutable
```

Use `crane digest nginx:1.25.3` or `skopeo inspect` to resolve a tag to its digest during CI/CD, then commit the pinned reference.

## Learn More

SLSA Level 1+ and NIST SP 800-190 recommend digest pinning for container supply chain integrity. See the Kubernetes images documentation for details.

**Affected resources:** kv-e2e-psa-pinned/Deployment/compliant-app

</details>

<details>
<summary>Remediation: liveness-readiness-probes (2 resources affected)</summary>

## Why This Matters

Without a liveness probe, Kubernetes cannot detect when a container has become unresponsive or deadlocked. The container continues running and consuming resources while failing to serve traffic. Users experience timeouts and errors until someone manually intervenes.

## How to Fix

Add a liveness probe that checks the container's health:

```yaml
containers:
  - name: app
    livenessProbe:
      httpGet:
        path: /healthz
        port: 8080
      initialDelaySeconds: 15
      periodSeconds: 10
      failureThreshold: 3
```

Use `httpGet` for HTTP services, `tcpSocket` for TCP services, or `exec` with a custom health check script for non-network workloads.

## Learn More

See the Kubernetes documentation on container probes. Set initialDelaySeconds high enough for your application to start, and consider adding a startupProbe for slow-starting containers.

**Affected resources:** kv-e2e-psa-pinned/Deployment/compliant-app, kv-e2e-psa-pinned/Deployment/compliant-app

</details>

<details>
<summary>Remediation: priority-class-missing (1 resources affected)</summary>

## Why This Matters

Without a PriorityClass, pods receive default priority (typically 0) and are among the first to be evicted during resource pressure or node maintenance. This means important application workloads may be killed before less critical ones, leading to unpredictable outages.

## How to Fix

Define PriorityClasses for your workloads and assign them appropriately:

```yaml
apiVersion: scheduling.k8s.io/v1
kind: PriorityClass
metadata:
  name: app-medium
value: 100000
---
# Reference in your workload:
spec:
  priorityClassName: app-medium
```

Create a tiered priority scheme (e.g., app-critical: 500000, app-medium: 100000, app-low: 10000) that reflects your workload importance hierarchy.

## Learn More

Refer to the Kubernetes Pod Priority and Preemption documentation. Establishing a consistent priority scheme across namespaces ensures predictable eviction behavior during resource contention.

**Affected resources:** kv-e2e-psa-pinned/Deployment/compliant-app

</details>

<details>
<summary>Remediation: runtime-class (1 resources affected)</summary>

## Why This Matters

Without a RuntimeClass, pods use the default container runtime (typically runc), which shares the host kernel directly with containers. A kernel vulnerability can allow container escape to the host. Sandboxed runtimes like gVisor or Kata Containers add an additional isolation layer that intercepts system calls or runs containers in lightweight VMs.

## How to Fix

Specify a sandboxed RuntimeClass in the pod spec:

```yaml
spec:
  runtimeClassName: gvisor
```

Available RuntimeClasses depend on your cluster configuration. Common options include `gvisor` (user-space kernel), `kata` (micro-VMs), and `firecracker`. Check your cluster's available RuntimeClasses with `kubectl get runtimeclasses`.

## Learn More

Sandboxed runtimes are especially important for multi-tenant clusters and workloads processing untrusted input. They add latency overhead, so evaluate performance requirements. See the Kubernetes RuntimeClass documentation.

**Affected resources:** kv-e2e-psa-pinned/Deployment/compliant-app

</details>

<details>
<summary>Remediation: topology-spread (1 resources affected)</summary>

## Why This Matters

Without topology spread constraints, the scheduler may place all replicas on the same node or in the same availability zone. If that node or zone fails, your entire service goes down despite having multiple replicas. This negates the high-availability benefits of running multiple pods.

## How to Fix

Add topology spread constraints to distribute replicas across failure domains:

```yaml
spec:
  topologySpreadConstraints:
    - maxSkew: 1
      topologyKey: kubernetes.io/hostname
      whenUnsatisfiable: DoNotSchedule
      labelSelector:
        matchLabels:
          app: my-app
    - maxSkew: 1
      topologyKey: topology.kubernetes.io/zone
      whenUnsatisfiable: ScheduleAnyway
```

Use `kubernetes.io/hostname` for node-level spreading and `topology.kubernetes.io/zone` for zone-level spreading.

## Learn More

See the Kubernetes Pod Topology Spread Constraints documentation. Combining hostname and zone constraints provides both node-level and zone-level fault tolerance.

**Affected resources:** kv-e2e-psa-pinned/Deployment/compliant-app

</details>

<details>
<summary>Remediation: limit-range-missing (1 resources affected)</summary>

## Why This Matters

Without a LimitRange, any container can be created without resource constraints. A single runaway or malicious pod can consume all node CPU and memory, causing denial of service for other workloads on the same node.

## How to Fix

Create a LimitRange in the namespace to set default and maximum resource constraints:

```yaml
apiVersion: v1
kind: LimitRange
metadata:
  name: default-limits
  namespace: my-app
spec:
  limits:
    - type: Container
      default:
        cpu: 500m
        memory: 256Mi
      defaultRequest:
        cpu: 100m
        memory: 128Mi
      max:
        cpu: "2"
        memory: 1Gi
```

Containers that omit resource requests/limits will inherit these defaults automatically.

## Learn More

CIS Kubernetes Benchmark 5.2.1 recommends LimitRanges for resource governance. See https://kubernetes.io/docs/concepts/policy/limit-range/ for configuration details.

**Affected resources:** kv-e2e-psa-pinned/Namespace/kv-e2e-psa-pinned

</details>

<details>
<summary>Remediation: psa-version-pinning (3 resources affected)</summary>

## Why This Matters

When a PSA version label is pinned to a specific Kubernetes version, the namespace will not automatically benefit from new security restrictions added in later versions. After a cluster upgrade, workloads may be allowed to run configurations that the newer Pod Security Standards would otherwise block.

## How to Fix

Set the version label to "latest" so it always uses the security standards matching the current cluster version:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: my-namespace
  labels:
    pod-security.kubernetes.io/enforce-version: "latest"
```

If pinning is intentional (e.g., for compatibility testing), document the reason and plan to update after validation.

## Learn More

See the Kubernetes Pod Security Admission documentation on version labels. Using "latest" ensures your namespaces always apply the most up-to-date Pod Security Standards for the cluster version.

**Affected resources:** kv-e2e-psa-pinned/Namespace/kv-e2e-psa-pinned, kv-e2e-psa-pinned/Namespace/kv-e2e-psa-pinned, kv-e2e-psa-pinned/Namespace/kv-e2e-psa-pinned

</details>

<details>
<summary>Remediation: resource-quota-missing (1 resources affected)</summary>

## Why This Matters

Without a ResourceQuota, a single namespace can consume the entire cluster's CPU, memory, and storage. This creates a noisy-neighbor problem where one team's workloads starve others, and makes capacity planning impossible.

## How to Fix

Create a ResourceQuota to cap the namespace's total resource consumption:

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: compute-quota
  namespace: my-app
spec:
  hard:
    requests.cpu: "10"
    requests.memory: 20Gi
    limits.cpu: "20"
    limits.memory: 40Gi
    pods: "50"
    services: "10"
```

Tune quota values based on the namespace's actual workload requirements and cluster capacity.

## Learn More

CIS Kubernetes Benchmark 5.2.2 recommends ResourceQuotas for multi-tenant clusters. See https://kubernetes.io/docs/concepts/policy/resource-quotas/ for quota configuration and enforcement behavior.

**Affected resources:** kv-e2e-psa-pinned/Namespace/kv-e2e-psa-pinned

</details>

### kv-e2e-psa-restricted (71 findings — 🟠12 🟡36 🔵23)

| Severity | Check | Resources | Message | Frameworks |
|----------|-------|-----------|---------|-----------|
| 🟠 High | automount-token | **3 resources** | Deployment "explicit-root-app" auto-mounts a ServiceAccount token. Most workloads do not need Kubernetes API access. | CIS 5.1.6 · MITRE T1552.007 · NSA 3.2 |
| 🟠 High | default-service-account | **3 resources** | Deployment "explicit-root-app" uses the default ServiceAccount, which may have unintended permissions. | CIS 5.1.5 · CIS 5.1.6 · MITRE T1078.001 · NSA 3.1 · NSA 3.2 |
| 🟠 High | privilege-escalation | **3 resources** | Container "pause" does not set allowPrivilegeEscalation to false, permitting privilege escalation. | CIS 5.2.6 · MITRE T1068 · MITRE T1611 · NSA 1.1 · NSA 2.1 |
| 🟠 High | run-as-root | **2 resources** | Container "pause" is explicitly configured to run as root (UID 0). | CIS 5.2.7 · MITRE T1611 · NSA 1.1 |
| 🟠 High | network-policy-missing | kv-e2e-psa-restricted/Namespace/kv-e2e-psa-restricted | Namespace "kv-e2e-psa-restricted" has no NetworkPolicy defined. All pods are unrestricted. | CIS 5.3.2 · MITRE T1046 · NSA 4.1 · NSA 4.2 |
| 🟡 Medium | apparmor-profile | **3 resources** | Container "pause" does not have an AppArmor profile set. | CIS 5.6.3 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | capabilities-not-dropped | **3 resources** | Container "pause" does not drop ALL capabilities, leaving it with unnecessary default privileges. | CIS 5.2.8 · CIS 5.2.10 · MITRE T1068 · NSA 1.1 |
| 🟡 Medium | image-pull-policy | **3 resources** | Container "pause" uses a mutable image tag with pullPolicy "IfNotPresent" (image: registry.k8s.io/pause:3.9), risking stale images. | CIS 5.5.1 · MITRE T1525 · NSA 1.4 |
| 🟡 Medium | psa-restricted-violations | **8 resources** | Deployment "explicit-root-app" container "pause" violates PSS Restricted: runAsNonRoot is not true. | CIS 5.2.1 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | resource-limits-missing | **3 resources** | Container "pause" is missing both CPU and memory limits. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🟡 Medium | resource-requests-missing | **3 resources** | Container "pause" is missing both CPU and memory requests. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🟡 Medium | run-as-group | **2 resources** | Container "pause" does not set runAsGroup; the process will run as GID 0 (root group) by default. | CIS 5.2.7 · MITRE T1068 · NSA 1.1 |
| 🟡 Medium | seccomp-profile | **3 resources** | Container "pause" does not have a Seccomp profile set at either the container or pod level. | CIS 5.6.2 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | token-projection-config | **3 resources** | Deployment "explicit-root-app" does not use explicitly configured projected ServiceAccount tokens with expiry and audience restrictions. | CIS 5.1.6 · MITRE T1552.007 · NSA 3.2 |
| 🟡 Medium | network-policy-egress-unrestricted | kv-e2e-psa-restricted/Namespace/kv-e2e-psa-restricted | Namespace "kv-e2e-psa-restricted" has no NetworkPolicy with egress restrictions. Pods can reach any external destination. | CIS 5.3.2 · MITRE T1048 · NSA 4.2 |
| 🟡 Medium | psa-labels-missing | kv-e2e-psa-restricted/Namespace/kv-e2e-psa-restricted | Namespace "kv-e2e-psa-restricted" is missing the pod-security.kubernetes.io/enforce label; pod security is not enforced. | CIS 5.2.1 · MITRE T1610 · NSA 2.1 |
| 🟡 Medium | psa-mode-audit-only | kv-e2e-psa-restricted/Namespace/kv-e2e-psa-restricted | Namespace "kv-e2e-psa-restricted" has PSA audit/warn labels but no enforce label; violations are logged but not blocked. | CIS 5.2.1 · MITRE T1610 · NSA 2.1 |
| 🟡 Medium | read-only-rootfs | **2 resources** | Container "pause" does not have a read-only root filesystem. | CIS 5.6.3 · MITRE T1565.001 · NSA 1.2 |
| 🔵 Low | ephemeral-storage-limits | **3 resources** | Container "pause" is missing ephemeral-storage limits. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | image-no-digest | **3 resources** | Container "pause" image is not pinned by digest (image: registry.k8s.io/pause:3.9), allowing tag mutation. | CIS 5.5.1 · MITRE T1525 · NSA 1.4 |
| 🔵 Low | liveness-readiness-probes | **6 resources** | Container "pause" has no liveness probe configured. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | priority-class-missing | **3 resources** | Deployment "explicit-root-app" has no PriorityClass set; it will be evicted first during resource pressure. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | runtime-class | **3 resources** | Pod "explicit-root-app" does not specify a RuntimeClass, using the default (unsandboxed) runtime. | CIS 5.6.3 · MITRE T1611 · NSA 2.1 |
| 🔵 Low | topology-spread | **3 resources** | Deployment "explicit-root-app" has no topology spread constraints; all replicas may be scheduled on the same node. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | limit-range-missing | kv-e2e-psa-restricted/Namespace/kv-e2e-psa-restricted | Namespace "kv-e2e-psa-restricted" has no LimitRange defined. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | resource-quota-missing | kv-e2e-psa-restricted/Namespace/kv-e2e-psa-restricted | Namespace "kv-e2e-psa-restricted" has no ResourceQuota defined. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |

<details>
<summary>automount-token: 3 affected resources</summary>

- `kv-e2e-psa-restricted/Deployment/explicit-root-app`
- `kv-e2e-psa-restricted/Deployment/no-security-context-app`
- `kv-e2e-psa-restricted/Deployment/partial-restricted-app`

</details>

<details>
<summary>default-service-account: 3 affected resources</summary>

- `kv-e2e-psa-restricted/Deployment/explicit-root-app`
- `kv-e2e-psa-restricted/Deployment/no-security-context-app`
- `kv-e2e-psa-restricted/Deployment/partial-restricted-app`

</details>

<details>
<summary>privilege-escalation: 3 affected resources</summary>

- `kv-e2e-psa-restricted/Deployment/explicit-root-app (pause)`
- `kv-e2e-psa-restricted/Deployment/no-security-context-app (pause)`
- `kv-e2e-psa-restricted/Deployment/partial-restricted-app (pause)`

</details>

<details>
<summary>run-as-root: 2 affected resources</summary>

- `kv-e2e-psa-restricted/Deployment/explicit-root-app (pause)`
- `kv-e2e-psa-restricted/Deployment/no-security-context-app (pause)`

</details>

<details>
<summary>apparmor-profile: 3 affected resources</summary>

- `kv-e2e-psa-restricted/Deployment/explicit-root-app (pause)`
- `kv-e2e-psa-restricted/Deployment/no-security-context-app (pause)`
- `kv-e2e-psa-restricted/Deployment/partial-restricted-app (pause)`

</details>

<details>
<summary>capabilities-not-dropped: 3 affected resources</summary>

- `kv-e2e-psa-restricted/Deployment/explicit-root-app (pause)`
- `kv-e2e-psa-restricted/Deployment/no-security-context-app (pause)`
- `kv-e2e-psa-restricted/Deployment/partial-restricted-app (pause)`

</details>

<details>
<summary>image-pull-policy: 3 affected resources</summary>

- `kv-e2e-psa-restricted/Deployment/explicit-root-app (pause)`
- `kv-e2e-psa-restricted/Deployment/no-security-context-app (pause)`
- `kv-e2e-psa-restricted/Deployment/partial-restricted-app (pause)`

</details>

<details>
<summary>psa-restricted-violations: 8 affected resources</summary>

- `kv-e2e-psa-restricted/Deployment/explicit-root-app (pause)`
- `kv-e2e-psa-restricted/Deployment/explicit-root-app (pause)`
- `kv-e2e-psa-restricted/Deployment/explicit-root-app (pause)`
- `kv-e2e-psa-restricted/Deployment/no-security-context-app (pause)`
- `kv-e2e-psa-restricted/Deployment/no-security-context-app (pause)`
- `kv-e2e-psa-restricted/Deployment/no-security-context-app (pause)`
- `kv-e2e-psa-restricted/Deployment/partial-restricted-app (pause)`
- `kv-e2e-psa-restricted/Deployment/partial-restricted-app (pause)`

</details>

<details>
<summary>resource-limits-missing: 3 affected resources</summary>

- `kv-e2e-psa-restricted/Deployment/explicit-root-app (pause)`
- `kv-e2e-psa-restricted/Deployment/no-security-context-app (pause)`
- `kv-e2e-psa-restricted/Deployment/partial-restricted-app (pause)`

</details>

<details>
<summary>resource-requests-missing: 3 affected resources</summary>

- `kv-e2e-psa-restricted/Deployment/explicit-root-app (pause)`
- `kv-e2e-psa-restricted/Deployment/no-security-context-app (pause)`
- `kv-e2e-psa-restricted/Deployment/partial-restricted-app (pause)`

</details>

<details>
<summary>run-as-group: 2 affected resources</summary>

- `kv-e2e-psa-restricted/Deployment/explicit-root-app (pause)`
- `kv-e2e-psa-restricted/Deployment/no-security-context-app (pause)`

</details>

<details>
<summary>seccomp-profile: 3 affected resources</summary>

- `kv-e2e-psa-restricted/Deployment/explicit-root-app (pause)`
- `kv-e2e-psa-restricted/Deployment/no-security-context-app (pause)`
- `kv-e2e-psa-restricted/Deployment/partial-restricted-app (pause)`

</details>

<details>
<summary>token-projection-config: 3 affected resources</summary>

- `kv-e2e-psa-restricted/Deployment/explicit-root-app`
- `kv-e2e-psa-restricted/Deployment/no-security-context-app`
- `kv-e2e-psa-restricted/Deployment/partial-restricted-app`

</details>

<details>
<summary>read-only-rootfs: 2 affected resources</summary>

- `kv-e2e-psa-restricted/Deployment/no-security-context-app (pause)`
- `kv-e2e-psa-restricted/Deployment/partial-restricted-app (pause)`

</details>

<details>
<summary>ephemeral-storage-limits: 3 affected resources</summary>

- `kv-e2e-psa-restricted/Deployment/explicit-root-app (pause)`
- `kv-e2e-psa-restricted/Deployment/no-security-context-app (pause)`
- `kv-e2e-psa-restricted/Deployment/partial-restricted-app (pause)`

</details>

<details>
<summary>image-no-digest: 3 affected resources</summary>

- `kv-e2e-psa-restricted/Deployment/explicit-root-app (pause)`
- `kv-e2e-psa-restricted/Deployment/no-security-context-app (pause)`
- `kv-e2e-psa-restricted/Deployment/partial-restricted-app (pause)`

</details>

<details>
<summary>liveness-readiness-probes: 6 affected resources</summary>

- `kv-e2e-psa-restricted/Deployment/explicit-root-app (pause)`
- `kv-e2e-psa-restricted/Deployment/explicit-root-app (pause)`
- `kv-e2e-psa-restricted/Deployment/no-security-context-app (pause)`
- `kv-e2e-psa-restricted/Deployment/no-security-context-app (pause)`
- `kv-e2e-psa-restricted/Deployment/partial-restricted-app (pause)`
- `kv-e2e-psa-restricted/Deployment/partial-restricted-app (pause)`

</details>

<details>
<summary>priority-class-missing: 3 affected resources</summary>

- `kv-e2e-psa-restricted/Deployment/explicit-root-app`
- `kv-e2e-psa-restricted/Deployment/no-security-context-app`
- `kv-e2e-psa-restricted/Deployment/partial-restricted-app`

</details>

<details>
<summary>runtime-class: 3 affected resources</summary>

- `kv-e2e-psa-restricted/Deployment/explicit-root-app`
- `kv-e2e-psa-restricted/Deployment/no-security-context-app`
- `kv-e2e-psa-restricted/Deployment/partial-restricted-app`

</details>

<details>
<summary>topology-spread: 3 affected resources</summary>

- `kv-e2e-psa-restricted/Deployment/explicit-root-app`
- `kv-e2e-psa-restricted/Deployment/no-security-context-app`
- `kv-e2e-psa-restricted/Deployment/partial-restricted-app`

</details>

<details>
<summary>Remediation: automount-token (3 resources affected)</summary>

## Why This Matters

When a ServiceAccount token is auto-mounted, every container in the pod can call the Kubernetes API. If a container is compromised through a vulnerability or misconfiguration, the attacker gains API access to enumerate resources, read secrets, or escalate privileges.

## How to Fix

Disable auto-mounting at the pod spec level for workloads that do not need API access:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      automountServiceAccountToken: false
      containers:
        - name: app
          image: my-app:latest
```

For workloads that do require API access, use projected tokens with bounded lifetime and audience restrictions instead of the default long-lived token.

## Learn More

Refer to the Kubernetes documentation on configuring service accounts for pods and CIS Kubernetes Benchmark 5.1.6 for auto-mount token guidance.

**Affected resources:** kv-e2e-psa-restricted/Deployment/explicit-root-app, kv-e2e-psa-restricted/Deployment/no-security-context-app, kv-e2e-psa-restricted/Deployment/partial-restricted-app

</details>

<details>
<summary>Remediation: default-service-account (3 resources affected)</summary>

## Why This Matters

The default ServiceAccount is shared by every pod in a namespace. If any pod is compromised, the attacker inherits whatever permissions have been granted to the default account via role bindings, enabling lateral movement across all workloads sharing it.

## How to Fix

Create a dedicated ServiceAccount for each workload and reference it in the pod spec:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-app
  namespace: production
automountServiceAccountToken: false
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      serviceAccountName: my-app
```

Grant only the permissions the workload actually needs via a dedicated Role and RoleBinding.

## Learn More

See the Kubernetes documentation on managing service accounts and CIS Kubernetes Benchmark 5.1.5 for guidance on ensuring default service accounts are not actively used.

**Affected resources:** kv-e2e-psa-restricted/Deployment/explicit-root-app, kv-e2e-psa-restricted/Deployment/no-security-context-app, kv-e2e-psa-restricted/Deployment/partial-restricted-app

</details>

<details>
<summary>Remediation: privilege-escalation (3 resources affected)</summary>

## Why This Matters

By default, Kubernetes allows containers to escalate privileges via setuid/setgid binaries, which let a process gain more permissions than its parent. An attacker can exploit this using setuid binaries already present in the container image (like `su`, `sudo`, or `ping`) to elevate from a low-privilege user to root.

## How to Fix

Explicitly disable privilege escalation in the container's securityContext:

```yaml
securityContext:
  allowPrivilegeEscalation: false
  runAsNonRoot: true
  capabilities:
    drop: ["ALL"]
```

This blocks the use of setuid/setgid binaries and prevents the no_new_privs Linux flag from being cleared. The vast majority of application containers do not need privilege escalation.

## Learn More

This is required by the Pod Security Standards "Restricted" profile and CIS Benchmark 5.2.5. Disabling privilege escalation is one of the most impactful single-line security improvements you can make.

**Affected resources:** kv-e2e-psa-restricted/Deployment/explicit-root-app, kv-e2e-psa-restricted/Deployment/no-security-context-app, kv-e2e-psa-restricted/Deployment/partial-restricted-app

</details>

<details>
<summary>Remediation: run-as-root (2 resources affected)</summary>

## Why This Matters

Running as root (UID 0) gives processes full privileges inside the container. If a container escape occurs, the attacker lands on the host as root, with the ability to access other containers, steal secrets, and compromise the entire node. This is the most common container security misconfiguration.

## How to Fix

Set a non-root user in the securityContext:

```yaml
securityContext:
  runAsUser: 1000
  runAsNonRoot: true
  runAsGroup: 1000
```

Also add a `USER` directive in your Dockerfile to ensure the image defaults to a non-root user. Most application frameworks (Node.js, Python, Go, Java) work correctly as non-root.

## Learn More

This aligns with CIS Benchmark 5.2.6 and the Pod Security Standards "Restricted" profile. Running as non-root is considered a foundational security practice for all container workloads.

**Affected resources:** kv-e2e-psa-restricted/Deployment/explicit-root-app, kv-e2e-psa-restricted/Deployment/no-security-context-app

</details>

<details>
<summary>Remediation: network-policy-missing (1 resources affected)</summary>

## Why This Matters

Without NetworkPolicies, every pod in this namespace can communicate freely with every other pod in the cluster. If an attacker compromises a single pod, they can move laterally to databases, internal APIs, and other sensitive services with no network-level barriers.

## How to Fix

Create a default-deny NetworkPolicy for the namespace, then add targeted allow rules for legitimate traffic:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: my-namespace
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
```

After applying the default-deny, create additional NetworkPolicy resources that whitelist only the specific ingress and egress flows your workloads require.

## Learn More

See the Kubernetes documentation on NetworkPolicies and CIS Kubernetes Benchmark 5.3.2. A CNI plugin that supports NetworkPolicy (Calico, Cilium, Weave Net) must be installed for policies to take effect.

**Affected resources:** kv-e2e-psa-restricted/Namespace/kv-e2e-psa-restricted

</details>

<details>
<summary>Remediation: apparmor-profile (3 resources affected)</summary>

## Why This Matters

AppArmor provides mandatory access control (MAC) that restricts which files, network resources, and capabilities a container process can access. Without an AppArmor profile, the container operates without these restrictions, allowing an attacker with code execution to access any file the container user can read and make unrestricted network connections.

## How to Fix

Apply an AppArmor profile in the container's securityContext (Kubernetes 1.30+):

```yaml
securityContext:
  appArmorProfile:
    type: RuntimeDefault
```

The RuntimeDefault profile provides sensible restrictions for most applications. For tighter control, create a custom Localhost profile that only allows the specific file and network access your application needs.

## Learn More

AppArmor is available on Debian/Ubuntu-based nodes. RHEL/CentOS nodes use SELinux instead. Both provide MAC enforcement. Refer to CIS Benchmark 5.7.5 and the Kubernetes AppArmor documentation.

**Affected resources:** kv-e2e-psa-restricted/Deployment/explicit-root-app, kv-e2e-psa-restricted/Deployment/no-security-context-app, kv-e2e-psa-restricted/Deployment/partial-restricted-app

</details>

<details>
<summary>Remediation: capabilities-not-dropped (3 resources affected)</summary>

## Why This Matters

By default, containers receive a set of Linux capabilities including KILL, SETUID, SETGID, and NET_RAW. These defaults are rarely needed by application code and significantly increase the potential damage from a container compromise. Dropping all capabilities follows the principle of least privilege.

## How to Fix

Explicitly drop all capabilities and selectively add back only what your application needs:

```yaml
securityContext:
  capabilities:
    drop: ["ALL"]
    add: ["NET_BIND_SERVICE"]  # Only if needed
```

Most web applications, API servers, and background workers run perfectly with all capabilities dropped. Test your application after making this change to confirm no functionality is lost.

## Learn More

This is required by the Pod Security Standards "Restricted" profile and aligns with CIS Benchmark 5.2.7. Kubernetes best practice is to treat capability grants as exceptions that require explicit justification.

**Affected resources:** kv-e2e-psa-restricted/Deployment/explicit-root-app, kv-e2e-psa-restricted/Deployment/no-security-context-app, kv-e2e-psa-restricted/Deployment/partial-restricted-app

</details>

<details>
<summary>Remediation: image-pull-policy (3 resources affected)</summary>

## Why This Matters

When a mutable image tag is used without `imagePullPolicy: Always`, Kubernetes may serve a cached version of the image from the node. If the tag has been updated in the registry (with a security patch or -- worse -- a compromised layer), the running container will not reflect those changes.

## How to Fix

Set `imagePullPolicy: Always` for any container using a mutable tag:

```yaml
containers:
  - name: app
    image: nginx:1.25.3
    imagePullPolicy: Always   # Forces fresh pull each time
```

Alternatively, pin images by digest (`image@sha256:...`), which makes the pull policy irrelevant because the content is immutable.

## Learn More

See the Kubernetes documentation on image pull policies and CIS Kubernetes Benchmark 5.4.2 for pull policy guidance.

**Affected resources:** kv-e2e-psa-restricted/Deployment/explicit-root-app, kv-e2e-psa-restricted/Deployment/no-security-context-app, kv-e2e-psa-restricted/Deployment/partial-restricted-app

</details>

<details>
<summary>Remediation: psa-restricted-violations (8 resources affected)</summary>

## Why This Matters

Running as root inside a container means that any container escape vulnerability immediately grants root access on the host node. Even without an escape, root inside the container can modify sensitive files, install packages, and access capabilities that non-root users cannot.

## How to Fix

Set `runAsNonRoot: true` and specify a non-root user ID in the security context:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
```

Set this at the pod level to apply to all containers. Ensure your container image supports running as a non-root user (many official images do).

## Learn More

See the Pod Security Standards Restricted profile and CIS Kubernetes Benchmark 5.2.6. Running as non-root is a fundamental container security best practice.

**Affected resources:** kv-e2e-psa-restricted/Deployment/explicit-root-app, kv-e2e-psa-restricted/Deployment/explicit-root-app, kv-e2e-psa-restricted/Deployment/explicit-root-app, kv-e2e-psa-restricted/Deployment/no-security-context-app, kv-e2e-psa-restricted/Deployment/no-security-context-app, kv-e2e-psa-restricted/Deployment/no-security-context-app, kv-e2e-psa-restricted/Deployment/partial-restricted-app, kv-e2e-psa-restricted/Deployment/partial-restricted-app

</details>

<details>
<summary>Remediation: resource-limits-missing (3 resources affected)</summary>

## Why This Matters

Without resource limits, a single container can consume all available CPU and memory on a node, starving other workloads and triggering cascading failures. An attacker who compromises an unlimited container can mount a denial-of-service attack against the entire node with a simple fork bomb or memory allocation loop.

## How to Fix

Set both CPU and memory limits based on your application's actual resource usage:

```yaml
resources:
  limits:
    cpu: 500m
    memory: 256Mi
  requests:
    cpu: 100m
    memory: 128Mi
```

Profile your application under load to determine appropriate values. Set limits to handle peak usage and requests to match steady-state consumption.

## Learn More

Use LimitRange objects to enforce default limits at the namespace level. Resource limits also determine the pod's QoS class: pods with equal requests and limits get Guaranteed QoS and are last to be evicted.

**Affected resources:** kv-e2e-psa-restricted/Deployment/explicit-root-app, kv-e2e-psa-restricted/Deployment/no-security-context-app, kv-e2e-psa-restricted/Deployment/partial-restricted-app

</details>

<details>
<summary>Remediation: resource-requests-missing (3 resources affected)</summary>

## Why This Matters

Resource requests tell the Kubernetes scheduler how much CPU and memory your container needs. Without requests, the scheduler treats the pod as needing zero resources and may pack too many pods onto a single node. This leads to overcommitment, resource contention, throttling, and OOM kills under load.

## How to Fix

Set resource requests based on your application's steady-state usage:

```yaml
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 256Mi
```

Observe your application's actual resource consumption using `kubectl top` or a monitoring tool, then set requests to match the typical steady-state usage.

## Learn More

Resource requests determine the pod's QoS class and scheduling behavior. Pods with requests equal to limits receive Guaranteed QoS. Use Vertical Pod Autoscaler (VPA) to automatically recommend request values.

**Affected resources:** kv-e2e-psa-restricted/Deployment/explicit-root-app, kv-e2e-psa-restricted/Deployment/no-security-context-app, kv-e2e-psa-restricted/Deployment/partial-restricted-app

</details>

<details>
<summary>Remediation: run-as-group (2 resources affected)</summary>

## Why This Matters

Without an explicit runAsGroup, the container process defaults to GID 0 (the root group). Files and sockets owned by the root group become accessible to the container, including potentially sensitive host files if volumes are mounted. This widens the attack surface unnecessarily.

## How to Fix

Set an explicit non-root group in the securityContext:

```yaml
securityContext:
  runAsGroup: 1000
  runAsUser: 1000
  runAsNonRoot: true
```

Ensure the container image's application files and directories are readable by the specified GID. You may need to adjust file ownership in your Dockerfile with `chown`.

## Learn More

This aligns with CIS Benchmark 5.2.6 and the Pod Security Standards "Restricted" profile. Always set runAsUser, runAsGroup, and runAsNonRoot together for comprehensive identity control.

**Affected resources:** kv-e2e-psa-restricted/Deployment/explicit-root-app, kv-e2e-psa-restricted/Deployment/no-security-context-app

</details>

<details>
<summary>Remediation: seccomp-profile (3 resources affected)</summary>

## Why This Matters

Without a Seccomp profile, containers can invoke any of the 300+ Linux system calls, leaving the entire kernel attack surface exposed. Kernel vulnerabilities in obscure syscalls are a primary vector for container escapes. Seccomp filtering blocks dangerous syscalls that legitimate applications never use.

## How to Fix

Apply a Seccomp profile at the container or pod level:

```yaml
securityContext:
  seccompProfile:
    type: RuntimeDefault
```

The RuntimeDefault profile blocks approximately 50 dangerous syscalls while allowing normal application behavior. For stricter controls, use a custom Localhost profile tailored to your application's needs. Set the profile at the pod level to apply it to all containers.

## Learn More

Seccomp profiles are required by the Pod Security Standards "Restricted" profile and CIS Benchmark 5.7.2. Use tools like `strace` or the Security Profiles Operator to generate custom profiles for your workloads.

**Affected resources:** kv-e2e-psa-restricted/Deployment/explicit-root-app, kv-e2e-psa-restricted/Deployment/no-security-context-app, kv-e2e-psa-restricted/Deployment/partial-restricted-app

</details>

<details>
<summary>Remediation: token-projection-config (3 resources affected)</summary>

## Why This Matters

Without explicit projection configuration, ServiceAccount tokens use Kubernetes defaults: no audience restriction and a long expiration. A stolen token remains valid for an extended period and can be used against any API server endpoint, widening the blast radius of a compromise.

## How to Fix

Add a projected volume with explicit expiration and audience:

```yaml
spec:
  volumes:
    - name: token
      projected:
        sources:
          - serviceAccountToken:
              expirationSeconds: 3600
              audience: my-api
              path: token
  containers:
    - name: app
      volumeMounts:
        - name: token
          mountPath: /var/run/secrets/tokens
          readOnly: true
```

Projected tokens auto-rotate before expiry and are rejected by endpoints outside the specified audience.

## Learn More

See the Kubernetes documentation on projected volumes and service account token volume projection for detailed configuration options.

**Affected resources:** kv-e2e-psa-restricted/Deployment/explicit-root-app, kv-e2e-psa-restricted/Deployment/no-security-context-app, kv-e2e-psa-restricted/Deployment/partial-restricted-app

</details>

<details>
<summary>Remediation: network-policy-egress-unrestricted (1 resources affected)</summary>

## Why This Matters

Without any egress NetworkPolicy in this namespace, pods can freely send traffic to any destination including the public internet. A compromised pod can exfiltrate sensitive data, reach cloud metadata services (e.g., 169.254.169.254), or establish reverse shells to attacker-controlled servers.

## How to Fix

Create a NetworkPolicy with `Egress` in `policyTypes` to restrict outbound traffic. At minimum, allow DNS resolution:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-egress
  namespace: my-namespace
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector: {}
      ports:
        - port: 53
          protocol: UDP
```

Add additional egress rules for specific services your workloads need to reach.

## Learn More

See the Kubernetes NetworkPolicy documentation and CIS Kubernetes Benchmark 5.3.2. Egress controls are a key defense-in-depth measure recommended by the NSA/CISA Kubernetes Hardening Guide.

**Affected resources:** kv-e2e-psa-restricted/Namespace/kv-e2e-psa-restricted

</details>

<details>
<summary>Remediation: psa-labels-missing (1 resources affected)</summary>

## Why This Matters

Without PSA enforcement labels, any pod configuration is allowed in this namespace, including privileged containers, host namespace access, and root execution. This bypasses Kubernetes' built-in Pod Security Standards and leaves the namespace vulnerable to workloads that could compromise the node.

## How to Fix

Add Pod Security Admission labels to enforce a security profile on all pods in the namespace:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: kv-e2e-psa-restricted
  labels:
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

Start with `baseline` enforcement to block known privilege escalations, then upgrade to `restricted` after verifying all workloads are compliant.

## Learn More

See the Kubernetes Pod Security Admission documentation and CIS Kubernetes Benchmark 5.2. The three-tier approach (enforce, audit, warn) allows gradual adoption of stricter profiles.

**Affected resources:** kv-e2e-psa-restricted/Namespace/kv-e2e-psa-restricted

</details>

<details>
<summary>Remediation: psa-mode-audit-only (1 resources affected)</summary>

## Why This Matters

Audit and warn modes only log violations or show warnings to users -- they do not actually block non-compliant pods from being created. Without the `enforce` label, insecure workloads such as privileged containers or root-running pods can still be admitted to the namespace.

## How to Fix

Add the `enforce` label alongside the existing audit/warn labels to actively block non-compliant pods:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

Set `enforce` to `baseline` initially and review audit logs for `restricted` violations before upgrading the enforcement level.

## Learn More

See the Kubernetes Pod Security Admission documentation on modes (enforce, audit, warn). CIS Kubernetes Benchmark 5.2 recommends active enforcement of Pod Security Standards, not just auditing.

**Affected resources:** kv-e2e-psa-restricted/Namespace/kv-e2e-psa-restricted

</details>

<details>
<summary>Remediation: read-only-rootfs (2 resources affected)</summary>

## Why This Matters

A writable root filesystem allows an attacker who gains code execution in your container to modify application binaries, install attack tools, plant backdoors, or persist malware across container restarts. Making the filesystem read-only eliminates an entire class of post-exploitation techniques.

## How to Fix

Enable a read-only root filesystem and mount writable volumes only where needed:

```yaml
securityContext:
  readOnlyRootFilesystem: true
volumeMounts:
  - name: tmp
    mountPath: /tmp
volumes:
  - name: tmp
    emptyDir: {}
```

Common paths that need write access include /tmp, /var/cache, and /var/run. Mount each as an emptyDir or tmpfs volume rather than making the entire filesystem writable.

## Learn More

This aligns with CIS Benchmark 5.2.4 and the defense-in-depth principle. Combined with dropping capabilities and running as non-root, a read-only filesystem forms a strong container hardening baseline.

**Affected resources:** kv-e2e-psa-restricted/Deployment/no-security-context-app, kv-e2e-psa-restricted/Deployment/partial-restricted-app

</details>

<details>
<summary>Remediation: ephemeral-storage-limits (3 resources affected)</summary>

## Why This Matters

Ephemeral storage includes container logs, emptyDir volumes, and the writable container layer. Without limits, a single container can fill the node's root disk, triggering eviction of all pods on that node and potentially causing a cascading failure across your cluster. This is a common denial-of-service vector.

## How to Fix

Set ephemeral-storage limits alongside your CPU and memory limits:

```yaml
resources:
  limits:
    ephemeral-storage: 1Gi
  requests:
    ephemeral-storage: 500Mi
```

Estimate your application's disk usage from logs, temporary files, and cache data. If your application writes large temporary files, consider using a PersistentVolumeClaim instead of ephemeral storage.

## Learn More

The kubelet evicts pods that exceed their ephemeral-storage limit. Use LimitRange to set default ephemeral-storage limits at the namespace level to catch containers that omit this setting.

**Affected resources:** kv-e2e-psa-restricted/Deployment/explicit-root-app, kv-e2e-psa-restricted/Deployment/no-security-context-app, kv-e2e-psa-restricted/Deployment/partial-restricted-app

</details>

<details>
<summary>Remediation: image-no-digest (3 resources affected)</summary>

## Why This Matters

Image tags are mutable pointers -- a registry administrator or attacker can re-push a different image under the same tag. Without a digest, you have no cryptographic guarantee that the image you deploy is the one you tested.

## How to Fix

Pin images by their SHA-256 content digest for a fully immutable reference:

```yaml
containers:
  - name: app
    image: nginx@sha256:a8281ce420348a01ea6e   # Immutable
```

Use `crane digest nginx:1.25.3` or `skopeo inspect` to resolve a tag to its digest during CI/CD, then commit the pinned reference.

## Learn More

SLSA Level 1+ and NIST SP 800-190 recommend digest pinning for container supply chain integrity. See the Kubernetes images documentation for details.

**Affected resources:** kv-e2e-psa-restricted/Deployment/explicit-root-app, kv-e2e-psa-restricted/Deployment/no-security-context-app, kv-e2e-psa-restricted/Deployment/partial-restricted-app

</details>

<details>
<summary>Remediation: liveness-readiness-probes (6 resources affected)</summary>

## Why This Matters

Without a liveness probe, Kubernetes cannot detect when a container has become unresponsive or deadlocked. The container continues running and consuming resources while failing to serve traffic. Users experience timeouts and errors until someone manually intervenes.

## How to Fix

Add a liveness probe that checks the container's health:

```yaml
containers:
  - name: app
    livenessProbe:
      httpGet:
        path: /healthz
        port: 8080
      initialDelaySeconds: 15
      periodSeconds: 10
      failureThreshold: 3
```

Use `httpGet` for HTTP services, `tcpSocket` for TCP services, or `exec` with a custom health check script for non-network workloads.

## Learn More

See the Kubernetes documentation on container probes. Set initialDelaySeconds high enough for your application to start, and consider adding a startupProbe for slow-starting containers.

**Affected resources:** kv-e2e-psa-restricted/Deployment/explicit-root-app, kv-e2e-psa-restricted/Deployment/explicit-root-app, kv-e2e-psa-restricted/Deployment/no-security-context-app, kv-e2e-psa-restricted/Deployment/no-security-context-app, kv-e2e-psa-restricted/Deployment/partial-restricted-app, kv-e2e-psa-restricted/Deployment/partial-restricted-app

</details>

<details>
<summary>Remediation: priority-class-missing (3 resources affected)</summary>

## Why This Matters

Without a PriorityClass, pods receive default priority (typically 0) and are among the first to be evicted during resource pressure or node maintenance. This means important application workloads may be killed before less critical ones, leading to unpredictable outages.

## How to Fix

Define PriorityClasses for your workloads and assign them appropriately:

```yaml
apiVersion: scheduling.k8s.io/v1
kind: PriorityClass
metadata:
  name: app-medium
value: 100000
---
# Reference in your workload:
spec:
  priorityClassName: app-medium
```

Create a tiered priority scheme (e.g., app-critical: 500000, app-medium: 100000, app-low: 10000) that reflects your workload importance hierarchy.

## Learn More

Refer to the Kubernetes Pod Priority and Preemption documentation. Establishing a consistent priority scheme across namespaces ensures predictable eviction behavior during resource contention.

**Affected resources:** kv-e2e-psa-restricted/Deployment/explicit-root-app, kv-e2e-psa-restricted/Deployment/no-security-context-app, kv-e2e-psa-restricted/Deployment/partial-restricted-app

</details>

<details>
<summary>Remediation: runtime-class (3 resources affected)</summary>

## Why This Matters

Without a RuntimeClass, pods use the default container runtime (typically runc), which shares the host kernel directly with containers. A kernel vulnerability can allow container escape to the host. Sandboxed runtimes like gVisor or Kata Containers add an additional isolation layer that intercepts system calls or runs containers in lightweight VMs.

## How to Fix

Specify a sandboxed RuntimeClass in the pod spec:

```yaml
spec:
  runtimeClassName: gvisor
```

Available RuntimeClasses depend on your cluster configuration. Common options include `gvisor` (user-space kernel), `kata` (micro-VMs), and `firecracker`. Check your cluster's available RuntimeClasses with `kubectl get runtimeclasses`.

## Learn More

Sandboxed runtimes are especially important for multi-tenant clusters and workloads processing untrusted input. They add latency overhead, so evaluate performance requirements. See the Kubernetes RuntimeClass documentation.

**Affected resources:** kv-e2e-psa-restricted/Deployment/explicit-root-app, kv-e2e-psa-restricted/Deployment/no-security-context-app, kv-e2e-psa-restricted/Deployment/partial-restricted-app

</details>

<details>
<summary>Remediation: topology-spread (3 resources affected)</summary>

## Why This Matters

Without topology spread constraints, the scheduler may place all replicas on the same node or in the same availability zone. If that node or zone fails, your entire service goes down despite having multiple replicas. This negates the high-availability benefits of running multiple pods.

## How to Fix

Add topology spread constraints to distribute replicas across failure domains:

```yaml
spec:
  topologySpreadConstraints:
    - maxSkew: 1
      topologyKey: kubernetes.io/hostname
      whenUnsatisfiable: DoNotSchedule
      labelSelector:
        matchLabels:
          app: my-app
    - maxSkew: 1
      topologyKey: topology.kubernetes.io/zone
      whenUnsatisfiable: ScheduleAnyway
```

Use `kubernetes.io/hostname` for node-level spreading and `topology.kubernetes.io/zone` for zone-level spreading.

## Learn More

See the Kubernetes Pod Topology Spread Constraints documentation. Combining hostname and zone constraints provides both node-level and zone-level fault tolerance.

**Affected resources:** kv-e2e-psa-restricted/Deployment/explicit-root-app, kv-e2e-psa-restricted/Deployment/no-security-context-app, kv-e2e-psa-restricted/Deployment/partial-restricted-app

</details>

<details>
<summary>Remediation: limit-range-missing (1 resources affected)</summary>

## Why This Matters

Without a LimitRange, any container can be created without resource constraints. A single runaway or malicious pod can consume all node CPU and memory, causing denial of service for other workloads on the same node.

## How to Fix

Create a LimitRange in the namespace to set default and maximum resource constraints:

```yaml
apiVersion: v1
kind: LimitRange
metadata:
  name: default-limits
  namespace: my-app
spec:
  limits:
    - type: Container
      default:
        cpu: 500m
        memory: 256Mi
      defaultRequest:
        cpu: 100m
        memory: 128Mi
      max:
        cpu: "2"
        memory: 1Gi
```

Containers that omit resource requests/limits will inherit these defaults automatically.

## Learn More

CIS Kubernetes Benchmark 5.2.1 recommends LimitRanges for resource governance. See https://kubernetes.io/docs/concepts/policy/limit-range/ for configuration details.

**Affected resources:** kv-e2e-psa-restricted/Namespace/kv-e2e-psa-restricted

</details>

<details>
<summary>Remediation: resource-quota-missing (1 resources affected)</summary>

## Why This Matters

Without a ResourceQuota, a single namespace can consume the entire cluster's CPU, memory, and storage. This creates a noisy-neighbor problem where one team's workloads starve others, and makes capacity planning impossible.

## How to Fix

Create a ResourceQuota to cap the namespace's total resource consumption:

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: compute-quota
  namespace: my-app
spec:
  hard:
    requests.cpu: "10"
    requests.memory: 20Gi
    limits.cpu: "20"
    limits.memory: 40Gi
    pods: "50"
    services: "10"
```

Tune quota values based on the namespace's actual workload requirements and cluster capacity.

## Learn More

CIS Kubernetes Benchmark 5.2.2 recommends ResourceQuotas for multi-tenant clusters. See https://kubernetes.io/docs/concepts/policy/resource-quotas/ for quota configuration and enforcement behavior.

**Affected resources:** kv-e2e-psa-restricted/Namespace/kv-e2e-psa-restricted

</details>

### kv-e2e-rbac (54 findings — 🔴2 🟠11 🟡24 🔵16 ⬜1)

| Severity | Check | Resources | Message | Frameworks |
|----------|-------|-----------|---------|-----------|
| 🔴 Critical | rbac-escalation-verbs | kv-e2e-rbac/Role/kv-e2e-escalation-verbs | Role "kv-e2e-escalation-verbs" grants escalation verb "bind", allowing RBAC privilege escalation. | CIS 5.1.1 · CIS 5.1.8 · MITRE T1078 · MITRE T1068 · NSA 3.1 |
| 🔴 Critical | rbac-wildcard-verbs | kv-e2e-rbac/Role/kv-e2e-wildcard-verbs | Role "kv-e2e-wildcard-verbs" grants wildcard (*) verbs, violating least-privilege principle. | CIS 5.1.1 · CIS 5.1.3 · MITRE T1078 · NSA 3.1 |
| 🟠 High | automount-token | **2 resources** | Pod "kv-e2e-automount-pod" auto-mounts a ServiceAccount token. Most workloads do not need Kubernetes API access. | CIS 5.1.6 · MITRE T1552.007 · NSA 3.2 |
| 🟠 High | default-service-account | kv-e2e-rbac/Pod/kv-e2e-automount-pod | Pod "kv-e2e-automount-pod" uses the default ServiceAccount, which may have unintended permissions. | CIS 5.1.5 · CIS 5.1.6 · MITRE T1078.001 · NSA 3.1 · NSA 3.2 |
| 🟠 High | privilege-escalation | **2 resources** | Container "app" does not set allowPrivilegeEscalation to false, permitting privilege escalation. | CIS 5.2.6 · MITRE T1068 · MITRE T1611 · NSA 1.1 · NSA 2.1 |
| 🟠 High | run-as-root | **2 resources** | Container "app" does not set runAsNonRoot: true and may run as root. | CIS 5.2.7 · MITRE T1611 · NSA 1.1 |
| 🟠 High | rbac-exec-access | kv-e2e-rbac/Role/kv-e2e-exec-log-access | Role "kv-e2e-exec-log-access" grants exec/attach access to pods, equivalent to SSH access. | CIS 5.1.1 · MITRE T1609 · NSA 3.1 |
| 🟠 High | rbac-secret-access | **2 resources** | Role "kv-e2e-overly-broad" grants read access to Secrets, which may contain credentials and TLS keys. | CIS 5.1.2 · MITRE T1552 · NSA 3.1 · NSA 5.1 |
| 🟠 High | network-policy-missing | kv-e2e-rbac/Namespace/kv-e2e-rbac | Namespace "kv-e2e-rbac" has no NetworkPolicy defined. All pods are unrestricted. | CIS 5.3.2 · MITRE T1046 · NSA 4.1 · NSA 4.2 |
| 🟡 Medium | apparmor-profile | **2 resources** | Container "app" does not have an AppArmor profile set. | CIS 5.6.3 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | capabilities-not-dropped | **2 resources** | Container "app" does not drop ALL capabilities, leaving it with unnecessary default privileges. | CIS 5.2.8 · CIS 5.2.10 · MITRE T1068 · NSA 1.1 |
| 🟡 Medium | image-pull-policy | **2 resources** | Container "app" uses a mutable image tag with pullPolicy "IfNotPresent" (image: nginx:1.25), risking stale images. | CIS 5.5.1 · MITRE T1525 · NSA 1.4 |
| 🟡 Medium | projected-volume-security | **2 resources** | Pod "kv-e2e-automount-pod" has projected volume "kube-api-access-58rdd" with defaultMode 0644 which is too permissive. | CIS 5.4.1 · MITRE T1552 · NSA 5.1 |
| 🟡 Medium | psa-restricted-violations | **6 resources** | Pod "kv-e2e-automount-pod" container "app" violates PSS Restricted: runAsNonRoot is not true. | CIS 5.2.1 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | read-only-rootfs | **2 resources** | Container "app" does not have a read-only root filesystem. | CIS 5.6.3 · MITRE T1565.001 · NSA 1.2 |
| 🟡 Medium | run-as-group | **2 resources** | Container "app" does not set runAsGroup; the process will run as GID 0 (root group) by default. | CIS 5.2.7 · MITRE T1068 · NSA 1.1 |
| 🟡 Medium | seccomp-profile | **2 resources** | Container "app" does not have a Seccomp profile set at either the container or pod level. | CIS 5.6.2 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | cloud-iam-binding | kv-e2e-rbac/ServiceAccount/kv-e2e-cloud-iam-sa | ServiceAccount "kv-e2e-cloud-iam-sa" has AWS IRSA binding (eks.amazonaws.com/role-arn=arn:aws:iam::123456789012:role/kv-e2e-test-role). Verify the cloud IAM role follows least-privilege. | CIS 5.1.1 · MITRE T1078.004 · NSA 3.1 · NSA 3.2 |
| 🟡 Medium | rbac-log-access | kv-e2e-rbac/Role/kv-e2e-exec-log-access | Role "kv-e2e-exec-log-access" grants access to pod logs, which may contain sensitive application data. | CIS 5.1.1 · MITRE T1530 · NSA 3.1 |
| 🟡 Medium | network-policy-egress-unrestricted | kv-e2e-rbac/Namespace/kv-e2e-rbac | Namespace "kv-e2e-rbac" has no NetworkPolicy with egress restrictions. Pods can reach any external destination. | CIS 5.3.2 · MITRE T1048 · NSA 4.2 |
| 🟡 Medium | psa-labels-missing | kv-e2e-rbac/Namespace/kv-e2e-rbac | Namespace "kv-e2e-rbac" is missing the pod-security.kubernetes.io/enforce label; pod security is not enforced. | CIS 5.2.1 · MITRE T1610 · NSA 2.1 |
| 🔵 Low | ephemeral-storage-limits | **2 resources** | Container "app" is missing ephemeral-storage limits. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | image-no-digest | **2 resources** | Container "app" image is not pinned by digest (image: nginx:1.25), allowing tag mutation. | CIS 5.5.1 · MITRE T1525 · NSA 1.4 |
| 🔵 Low | liveness-readiness-probes | **4 resources** | Container "app" has no liveness probe configured. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | priority-class-missing | **2 resources** | Pod "kv-e2e-automount-pod" has no PriorityClass set; it will be evicted first during resource pressure. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | runtime-class | **2 resources** | Pod "kv-e2e-automount-pod" does not specify a RuntimeClass, using the default (unsandboxed) runtime. | CIS 5.6.3 · MITRE T1611 · NSA 2.1 |
| 🔵 Low | topology-spread | **2 resources** | Pod "kv-e2e-automount-pod" has no topology spread constraints; all replicas may be scheduled on the same node. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | limit-range-missing | kv-e2e-rbac/Namespace/kv-e2e-rbac | Namespace "kv-e2e-rbac" has no LimitRange defined. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | resource-quota-missing | kv-e2e-rbac/Namespace/kv-e2e-rbac | Namespace "kv-e2e-rbac" has no ResourceQuota defined. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| ⬜ Info | rbac-unused-roles | kv-e2e-rbac/Role/kv-e2e-unused-role | Role "kv-e2e-unused-role" has no bindings and may be unused. | CIS 5.1.1 · MITRE T1078 · NSA 3.1 |

<details>
<summary>automount-token: 2 affected resources</summary>

- `kv-e2e-rbac/Pod/kv-e2e-automount-pod`
- `kv-e2e-rbac/Pod/kv-e2e-no-projection-pod`

</details>

<details>
<summary>privilege-escalation: 2 affected resources</summary>

- `kv-e2e-rbac/Pod/kv-e2e-automount-pod (app)`
- `kv-e2e-rbac/Pod/kv-e2e-no-projection-pod (app)`

</details>

<details>
<summary>run-as-root: 2 affected resources</summary>

- `kv-e2e-rbac/Pod/kv-e2e-automount-pod (app)`
- `kv-e2e-rbac/Pod/kv-e2e-no-projection-pod (app)`

</details>

<details>
<summary>rbac-secret-access: 2 affected resources</summary>

- `kv-e2e-rbac/Role/kv-e2e-overly-broad`
- `kv-e2e-rbac/Role/kv-e2e-secret-access`

</details>

<details>
<summary>apparmor-profile: 2 affected resources</summary>

- `kv-e2e-rbac/Pod/kv-e2e-automount-pod (app)`
- `kv-e2e-rbac/Pod/kv-e2e-no-projection-pod (app)`

</details>

<details>
<summary>capabilities-not-dropped: 2 affected resources</summary>

- `kv-e2e-rbac/Pod/kv-e2e-automount-pod (app)`
- `kv-e2e-rbac/Pod/kv-e2e-no-projection-pod (app)`

</details>

<details>
<summary>image-pull-policy: 2 affected resources</summary>

- `kv-e2e-rbac/Pod/kv-e2e-automount-pod (app)`
- `kv-e2e-rbac/Pod/kv-e2e-no-projection-pod (app)`

</details>

<details>
<summary>projected-volume-security: 2 affected resources</summary>

- `kv-e2e-rbac/Pod/kv-e2e-automount-pod`
- `kv-e2e-rbac/Pod/kv-e2e-no-projection-pod`

</details>

<details>
<summary>psa-restricted-violations: 6 affected resources</summary>

- `kv-e2e-rbac/Pod/kv-e2e-automount-pod (app)`
- `kv-e2e-rbac/Pod/kv-e2e-automount-pod (app)`
- `kv-e2e-rbac/Pod/kv-e2e-automount-pod (app)`
- `kv-e2e-rbac/Pod/kv-e2e-no-projection-pod (app)`
- `kv-e2e-rbac/Pod/kv-e2e-no-projection-pod (app)`
- `kv-e2e-rbac/Pod/kv-e2e-no-projection-pod (app)`

</details>

<details>
<summary>read-only-rootfs: 2 affected resources</summary>

- `kv-e2e-rbac/Pod/kv-e2e-automount-pod (app)`
- `kv-e2e-rbac/Pod/kv-e2e-no-projection-pod (app)`

</details>

<details>
<summary>run-as-group: 2 affected resources</summary>

- `kv-e2e-rbac/Pod/kv-e2e-automount-pod (app)`
- `kv-e2e-rbac/Pod/kv-e2e-no-projection-pod (app)`

</details>

<details>
<summary>seccomp-profile: 2 affected resources</summary>

- `kv-e2e-rbac/Pod/kv-e2e-automount-pod (app)`
- `kv-e2e-rbac/Pod/kv-e2e-no-projection-pod (app)`

</details>

<details>
<summary>ephemeral-storage-limits: 2 affected resources</summary>

- `kv-e2e-rbac/Pod/kv-e2e-automount-pod (app)`
- `kv-e2e-rbac/Pod/kv-e2e-no-projection-pod (app)`

</details>

<details>
<summary>image-no-digest: 2 affected resources</summary>

- `kv-e2e-rbac/Pod/kv-e2e-automount-pod (app)`
- `kv-e2e-rbac/Pod/kv-e2e-no-projection-pod (app)`

</details>

<details>
<summary>liveness-readiness-probes: 4 affected resources</summary>

- `kv-e2e-rbac/Pod/kv-e2e-automount-pod (app)`
- `kv-e2e-rbac/Pod/kv-e2e-automount-pod (app)`
- `kv-e2e-rbac/Pod/kv-e2e-no-projection-pod (app)`
- `kv-e2e-rbac/Pod/kv-e2e-no-projection-pod (app)`

</details>

<details>
<summary>priority-class-missing: 2 affected resources</summary>

- `kv-e2e-rbac/Pod/kv-e2e-automount-pod`
- `kv-e2e-rbac/Pod/kv-e2e-no-projection-pod`

</details>

<details>
<summary>runtime-class: 2 affected resources</summary>

- `kv-e2e-rbac/Pod/kv-e2e-automount-pod`
- `kv-e2e-rbac/Pod/kv-e2e-no-projection-pod`

</details>

<details>
<summary>topology-spread: 2 affected resources</summary>

- `kv-e2e-rbac/Pod/kv-e2e-automount-pod`
- `kv-e2e-rbac/Pod/kv-e2e-no-projection-pod`

</details>

<details>
<summary>Remediation: rbac-escalation-verbs (1 resources affected)</summary>

## Why This Matters

The `bind`, `escalate`, and `impersonate` verbs are special RBAC verbs that allow bypassing normal privilege restrictions. `bind` lets a user assign roles they do not hold, `escalate` lets a user grant permissions beyond their own, and `impersonate` lets a user act as another identity. Any of these can lead to full cluster compromise.

## How to Fix

Remove escalation verbs and replace with specific non-escalating verbs:

```yaml
rules:
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["roles", "rolebindings"]
    verbs: ["get", "list", "watch"]  # Read-only, no bind/escalate
```

Only cluster administrators and RBAC management controllers (e.g., the Kubernetes controller manager) should hold these verbs.

## Learn More

See CIS Kubernetes Benchmark 5.1.8 on privilege escalation prevention and the Kubernetes RBAC documentation section on escalation prevention restrictions.

**Affected resources:** kv-e2e-rbac/Role/kv-e2e-escalation-verbs

</details>

<details>
<summary>Remediation: rbac-wildcard-verbs (1 resources affected)</summary>

## Why This Matters

A wildcard verb (`*`) grants every possible action on the specified resources, including delete, patch, and create. An attacker who assumes this role can modify or destroy resources, exfiltrate data, or escalate privileges far beyond what the workload actually requires.

## How to Fix

Replace the wildcard with the specific verbs your application needs:

```yaml
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "watch"]  # Only read access
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["get", "update"]          # Read + update only
```

Enable Kubernetes audit logging and review the audit trail to identify which verbs are actually used before tightening permissions.

## Learn More

Refer to CIS Kubernetes Benchmark 5.1.3 and the Kubernetes RBAC documentation for guidance on applying the principle of least privilege to role definitions.

**Affected resources:** kv-e2e-rbac/Role/kv-e2e-wildcard-verbs

</details>

<details>
<summary>Remediation: automount-token (2 resources affected)</summary>

## Why This Matters

When a ServiceAccount token is auto-mounted, every container in the pod can call the Kubernetes API. If a container is compromised through a vulnerability or misconfiguration, the attacker gains API access to enumerate resources, read secrets, or escalate privileges.

## How to Fix

Disable auto-mounting at the pod spec level for workloads that do not need API access:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      automountServiceAccountToken: false
      containers:
        - name: app
          image: my-app:latest
```

For workloads that do require API access, use projected tokens with bounded lifetime and audience restrictions instead of the default long-lived token.

## Learn More

Refer to the Kubernetes documentation on configuring service accounts for pods and CIS Kubernetes Benchmark 5.1.6 for auto-mount token guidance.

**Affected resources:** kv-e2e-rbac/Pod/kv-e2e-automount-pod, kv-e2e-rbac/Pod/kv-e2e-no-projection-pod

</details>

<details>
<summary>Remediation: default-service-account (1 resources affected)</summary>

## Why This Matters

The default ServiceAccount is shared by every pod in a namespace. If any pod is compromised, the attacker inherits whatever permissions have been granted to the default account via role bindings, enabling lateral movement across all workloads sharing it.

## How to Fix

Create a dedicated ServiceAccount for each workload and reference it in the pod spec:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-app
  namespace: production
automountServiceAccountToken: false
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      serviceAccountName: my-app
```

Grant only the permissions the workload actually needs via a dedicated Role and RoleBinding.

## Learn More

See the Kubernetes documentation on managing service accounts and CIS Kubernetes Benchmark 5.1.5 for guidance on ensuring default service accounts are not actively used.

**Affected resources:** kv-e2e-rbac/Pod/kv-e2e-automount-pod

</details>

<details>
<summary>Remediation: privilege-escalation (2 resources affected)</summary>

## Why This Matters

By default, Kubernetes allows containers to escalate privileges via setuid/setgid binaries, which let a process gain more permissions than its parent. An attacker can exploit this using setuid binaries already present in the container image (like `su`, `sudo`, or `ping`) to elevate from a low-privilege user to root.

## How to Fix

Explicitly disable privilege escalation in the container's securityContext:

```yaml
securityContext:
  allowPrivilegeEscalation: false
  runAsNonRoot: true
  capabilities:
    drop: ["ALL"]
```

This blocks the use of setuid/setgid binaries and prevents the no_new_privs Linux flag from being cleared. The vast majority of application containers do not need privilege escalation.

## Learn More

This is required by the Pod Security Standards "Restricted" profile and CIS Benchmark 5.2.5. Disabling privilege escalation is one of the most impactful single-line security improvements you can make.

**Affected resources:** kv-e2e-rbac/Pod/kv-e2e-automount-pod, kv-e2e-rbac/Pod/kv-e2e-no-projection-pod

</details>

<details>
<summary>Remediation: run-as-root (2 resources affected)</summary>

## Why This Matters

Without `runAsNonRoot: true`, Kubernetes does not enforce non-root execution and the container may default to running as UID 0 depending on the image's USER directive. If the image defaults to root, the container process gains full privileges, increasing the blast radius of any compromise or container escape.

## How to Fix

Enforce non-root execution in the securityContext:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
```

With `runAsNonRoot: true`, Kubernetes will reject the pod at admission time if the container image attempts to run as root. Setting an explicit `runAsUser` provides an additional guarantee.

## Learn More

This aligns with CIS Benchmark 5.2.6 and the Pod Security Standards "Restricted" profile. The `runAsNonRoot` field acts as a safety net even when images change their default USER.

**Affected resources:** kv-e2e-rbac/Pod/kv-e2e-automount-pod, kv-e2e-rbac/Pod/kv-e2e-no-projection-pod

</details>

<details>
<summary>Remediation: rbac-exec-access (1 resources affected)</summary>

## Why This Matters

The `pods/exec` and `pods/attach` sub-resources grant the ability to run arbitrary commands inside running containers, which is functionally equivalent to SSH access. An attacker with exec access can read environment variables, access mounted secrets, install tools, and pivot to other systems on the network.

## How to Fix

Remove exec and attach sub-resources from the role rules:

```yaml
rules:
  - apiGroups: [""]
    resources: ["pods"]              # pods only, no sub-resources
    verbs: ["get", "list", "watch"]
  # Do NOT include:
  # resources: ["pods/exec", "pods/attach"]
```

If exec access is required for debugging, restrict it to specific namespaces and enable Kubernetes audit logging to monitor all exec sessions in production.

## Learn More

See CIS Kubernetes Benchmark 5.1.3 and MITRE ATT&CK technique T1609 (Container Administration Command) for the exec-based attack vector.

**Affected resources:** kv-e2e-rbac/Role/kv-e2e-exec-log-access

</details>

<details>
<summary>Remediation: rbac-secret-access (2 resources affected)</summary>

## Why This Matters

Roles granting read access to Secrets expose every credential in the namespace, including database passwords, TLS private keys, API tokens, and third-party credentials. A compromised workload with this access can exfiltrate all secrets and pivot to external systems.

## How to Fix

Restrict access to only the specific secrets your workload needs using `resourceNames`:

```yaml
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["my-app-tls", "my-app-db-creds"]
    verbs: ["get"]
```

For sensitive credentials, consider using an external secrets manager (HashiCorp Vault, AWS Secrets Manager, or GCP Secret Manager) with the External Secrets Operator.

## Learn More

See CIS Kubernetes Benchmark 5.1.2 on minimizing access to secrets and MITRE ATT&CK technique T1552 (Unsecured Credentials) for the threat model.

**Affected resources:** kv-e2e-rbac/Role/kv-e2e-overly-broad, kv-e2e-rbac/Role/kv-e2e-secret-access

</details>

<details>
<summary>Remediation: network-policy-missing (1 resources affected)</summary>

## Why This Matters

Without NetworkPolicies, every pod in this namespace can communicate freely with every other pod in the cluster. If an attacker compromises a single pod, they can move laterally to databases, internal APIs, and other sensitive services with no network-level barriers.

## How to Fix

Create a default-deny NetworkPolicy for the namespace, then add targeted allow rules for legitimate traffic:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: my-namespace
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
```

After applying the default-deny, create additional NetworkPolicy resources that whitelist only the specific ingress and egress flows your workloads require.

## Learn More

See the Kubernetes documentation on NetworkPolicies and CIS Kubernetes Benchmark 5.3.2. A CNI plugin that supports NetworkPolicy (Calico, Cilium, Weave Net) must be installed for policies to take effect.

**Affected resources:** kv-e2e-rbac/Namespace/kv-e2e-rbac

</details>

<details>
<summary>Remediation: apparmor-profile (2 resources affected)</summary>

## Why This Matters

AppArmor provides mandatory access control (MAC) that restricts which files, network resources, and capabilities a container process can access. Without an AppArmor profile, the container operates without these restrictions, allowing an attacker with code execution to access any file the container user can read and make unrestricted network connections.

## How to Fix

Apply an AppArmor profile in the container's securityContext (Kubernetes 1.30+):

```yaml
securityContext:
  appArmorProfile:
    type: RuntimeDefault
```

The RuntimeDefault profile provides sensible restrictions for most applications. For tighter control, create a custom Localhost profile that only allows the specific file and network access your application needs.

## Learn More

AppArmor is available on Debian/Ubuntu-based nodes. RHEL/CentOS nodes use SELinux instead. Both provide MAC enforcement. Refer to CIS Benchmark 5.7.5 and the Kubernetes AppArmor documentation.

**Affected resources:** kv-e2e-rbac/Pod/kv-e2e-automount-pod, kv-e2e-rbac/Pod/kv-e2e-no-projection-pod

</details>

<details>
<summary>Remediation: capabilities-not-dropped (2 resources affected)</summary>

## Why This Matters

By default, containers receive a set of Linux capabilities including KILL, SETUID, SETGID, and NET_RAW. These defaults are rarely needed by application code and significantly increase the potential damage from a container compromise. Dropping all capabilities follows the principle of least privilege.

## How to Fix

Explicitly drop all capabilities and selectively add back only what your application needs:

```yaml
securityContext:
  capabilities:
    drop: ["ALL"]
    add: ["NET_BIND_SERVICE"]  # Only if needed
```

Most web applications, API servers, and background workers run perfectly with all capabilities dropped. Test your application after making this change to confirm no functionality is lost.

## Learn More

This is required by the Pod Security Standards "Restricted" profile and aligns with CIS Benchmark 5.2.7. Kubernetes best practice is to treat capability grants as exceptions that require explicit justification.

**Affected resources:** kv-e2e-rbac/Pod/kv-e2e-automount-pod, kv-e2e-rbac/Pod/kv-e2e-no-projection-pod

</details>

<details>
<summary>Remediation: image-pull-policy (2 resources affected)</summary>

## Why This Matters

When a mutable image tag is used without `imagePullPolicy: Always`, Kubernetes may serve a cached version of the image from the node. If the tag has been updated in the registry (with a security patch or -- worse -- a compromised layer), the running container will not reflect those changes.

## How to Fix

Set `imagePullPolicy: Always` for any container using a mutable tag:

```yaml
containers:
  - name: app
    image: nginx:1.25.3
    imagePullPolicy: Always   # Forces fresh pull each time
```

Alternatively, pin images by digest (`image@sha256:...`), which makes the pull policy irrelevant because the content is immutable.

## Learn More

See the Kubernetes documentation on image pull policies and CIS Kubernetes Benchmark 5.4.2 for pull policy guidance.

**Affected resources:** kv-e2e-rbac/Pod/kv-e2e-automount-pod, kv-e2e-rbac/Pod/kv-e2e-no-projection-pod

</details>

<details>
<summary>Remediation: projected-volume-security (2 resources affected)</summary>

## Why This Matters

Projected volumes with overly permissive file modes allow any process in the pod to read sensitive data such as service account tokens and secrets. If a container is compromised, the attacker can easily harvest these credentials to escalate privileges or move laterally within the cluster.

## How to Fix

Reduce the defaultMode to restrict file access:

```yaml
spec:
  volumes:
    - name: kube-api-access-58rdd
      projected:
        defaultMode: 0400         # Owner read-only (was too permissive)
        sources:
          - serviceAccountToken:
              path: token
```

Use 0400 for read-only access or 0600 if the application must write to the mounted files.

## Learn More

See the Kubernetes Projected Volumes documentation for defaultMode details. The CIS Benchmark recommends file modes of 0600 or lower for sensitive volume mounts to limit exposure within the pod.

**Affected resources:** kv-e2e-rbac/Pod/kv-e2e-automount-pod, kv-e2e-rbac/Pod/kv-e2e-no-projection-pod

</details>

<details>
<summary>Remediation: psa-restricted-violations (6 resources affected)</summary>

## Why This Matters

Running as root inside a container means that any container escape vulnerability immediately grants root access on the host node. Even without an escape, root inside the container can modify sensitive files, install packages, and access capabilities that non-root users cannot.

## How to Fix

Set `runAsNonRoot: true` and specify a non-root user ID in the security context:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
```

Set this at the pod level to apply to all containers. Ensure your container image supports running as a non-root user (many official images do).

## Learn More

See the Pod Security Standards Restricted profile and CIS Kubernetes Benchmark 5.2.6. Running as non-root is a fundamental container security best practice.

**Affected resources:** kv-e2e-rbac/Pod/kv-e2e-automount-pod, kv-e2e-rbac/Pod/kv-e2e-automount-pod, kv-e2e-rbac/Pod/kv-e2e-automount-pod, kv-e2e-rbac/Pod/kv-e2e-no-projection-pod, kv-e2e-rbac/Pod/kv-e2e-no-projection-pod, kv-e2e-rbac/Pod/kv-e2e-no-projection-pod

</details>

<details>
<summary>Remediation: read-only-rootfs (2 resources affected)</summary>

## Why This Matters

A writable root filesystem allows an attacker who gains code execution in your container to modify application binaries, install attack tools, plant backdoors, or persist malware across container restarts. Making the filesystem read-only eliminates an entire class of post-exploitation techniques.

## How to Fix

Enable a read-only root filesystem and mount writable volumes only where needed:

```yaml
securityContext:
  readOnlyRootFilesystem: true
volumeMounts:
  - name: tmp
    mountPath: /tmp
volumes:
  - name: tmp
    emptyDir: {}
```

Common paths that need write access include /tmp, /var/cache, and /var/run. Mount each as an emptyDir or tmpfs volume rather than making the entire filesystem writable.

## Learn More

This aligns with CIS Benchmark 5.2.4 and the defense-in-depth principle. Combined with dropping capabilities and running as non-root, a read-only filesystem forms a strong container hardening baseline.

**Affected resources:** kv-e2e-rbac/Pod/kv-e2e-automount-pod, kv-e2e-rbac/Pod/kv-e2e-no-projection-pod

</details>

<details>
<summary>Remediation: run-as-group (2 resources affected)</summary>

## Why This Matters

Without an explicit runAsGroup, the container process defaults to GID 0 (the root group). Files and sockets owned by the root group become accessible to the container, including potentially sensitive host files if volumes are mounted. This widens the attack surface unnecessarily.

## How to Fix

Set an explicit non-root group in the securityContext:

```yaml
securityContext:
  runAsGroup: 1000
  runAsUser: 1000
  runAsNonRoot: true
```

Ensure the container image's application files and directories are readable by the specified GID. You may need to adjust file ownership in your Dockerfile with `chown`.

## Learn More

This aligns with CIS Benchmark 5.2.6 and the Pod Security Standards "Restricted" profile. Always set runAsUser, runAsGroup, and runAsNonRoot together for comprehensive identity control.

**Affected resources:** kv-e2e-rbac/Pod/kv-e2e-automount-pod, kv-e2e-rbac/Pod/kv-e2e-no-projection-pod

</details>

<details>
<summary>Remediation: seccomp-profile (2 resources affected)</summary>

## Why This Matters

Without a Seccomp profile, containers can invoke any of the 300+ Linux system calls, leaving the entire kernel attack surface exposed. Kernel vulnerabilities in obscure syscalls are a primary vector for container escapes. Seccomp filtering blocks dangerous syscalls that legitimate applications never use.

## How to Fix

Apply a Seccomp profile at the container or pod level:

```yaml
securityContext:
  seccompProfile:
    type: RuntimeDefault
```

The RuntimeDefault profile blocks approximately 50 dangerous syscalls while allowing normal application behavior. For stricter controls, use a custom Localhost profile tailored to your application's needs. Set the profile at the pod level to apply it to all containers.

## Learn More

Seccomp profiles are required by the Pod Security Standards "Restricted" profile and CIS Benchmark 5.7.2. Use tools like `strace` or the Security Profiles Operator to generate custom profiles for your workloads.

**Affected resources:** kv-e2e-rbac/Pod/kv-e2e-automount-pod, kv-e2e-rbac/Pod/kv-e2e-no-projection-pod

</details>

<details>
<summary>Remediation: cloud-iam-binding (1 resources affected)</summary>

## Why This Matters

Cloud IAM bindings (AWS IRSA, GCP Workload Identity, Azure Workload Identity) grant pods direct access to cloud provider APIs such as S3, BigQuery, or Key Vault. If the associated cloud IAM role has overly broad permissions, a compromised pod can access, modify, or delete cloud resources far beyond what the workload requires.

## How to Fix

Audit the referenced cloud IAM role and apply least-privilege:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-app
  annotations:
    # AWS — use a role scoped to specific resources:
    eks.amazonaws.com/role-arn: arn:aws:iam::123:role/my-app-minimal
    # GCP — use a service account with only needed permissions:
    iam.gke.io/gcp-service-account: my-app@project.iam.gserviceaccount.com
```

Ensure the cloud IAM role/policy has no wildcard actions or resources. Use condition keys to restrict access by namespace or service account where supported.

## Learn More

See the AWS IRSA, GCP Workload Identity, or Azure Workload Identity documentation for provider-specific guidance on scoping cloud IAM permissions for Kubernetes workloads.

**Affected resources:** kv-e2e-rbac/ServiceAccount/kv-e2e-cloud-iam-sa

</details>

<details>
<summary>Remediation: rbac-log-access (1 resources affected)</summary>

## Why This Matters

The `pods/log` sub-resource provides access to container stdout/stderr output. Applications frequently log sensitive data inadvertently, including authentication tokens, database connection strings, API keys, and personally identifiable information (PII). An attacker with log access can harvest these credentials without needing exec access.

## How to Fix

Remove the `pods/log` sub-resource and grant log access only to dedicated monitoring roles:

```yaml
rules:
  - apiGroups: [""]
    resources: ["pods"]              # pods only, no sub-resources
    verbs: ["get", "list", "watch"]
  # Grant pods/log only to monitoring-specific roles
```

Additionally, configure applications to avoid logging sensitive data. Use structured logging libraries that support field redaction.

## Learn More

See MITRE ATT&CK technique T1530 (Data from Cloud Storage) and the Kubernetes RBAC documentation on sub-resource access control.

**Affected resources:** kv-e2e-rbac/Role/kv-e2e-exec-log-access

</details>

<details>
<summary>Remediation: network-policy-egress-unrestricted (1 resources affected)</summary>

## Why This Matters

Without any egress NetworkPolicy in this namespace, pods can freely send traffic to any destination including the public internet. A compromised pod can exfiltrate sensitive data, reach cloud metadata services (e.g., 169.254.169.254), or establish reverse shells to attacker-controlled servers.

## How to Fix

Create a NetworkPolicy with `Egress` in `policyTypes` to restrict outbound traffic. At minimum, allow DNS resolution:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-egress
  namespace: my-namespace
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector: {}
      ports:
        - port: 53
          protocol: UDP
```

Add additional egress rules for specific services your workloads need to reach.

## Learn More

See the Kubernetes NetworkPolicy documentation and CIS Kubernetes Benchmark 5.3.2. Egress controls are a key defense-in-depth measure recommended by the NSA/CISA Kubernetes Hardening Guide.

**Affected resources:** kv-e2e-rbac/Namespace/kv-e2e-rbac

</details>

<details>
<summary>Remediation: psa-labels-missing (1 resources affected)</summary>

## Why This Matters

Without PSA enforcement labels, any pod configuration is allowed in this namespace, including privileged containers, host namespace access, and root execution. This bypasses Kubernetes' built-in Pod Security Standards and leaves the namespace vulnerable to workloads that could compromise the node.

## How to Fix

Add Pod Security Admission labels to enforce a security profile on all pods in the namespace:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: kv-e2e-rbac
  labels:
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

Start with `baseline` enforcement to block known privilege escalations, then upgrade to `restricted` after verifying all workloads are compliant.

## Learn More

See the Kubernetes Pod Security Admission documentation and CIS Kubernetes Benchmark 5.2. The three-tier approach (enforce, audit, warn) allows gradual adoption of stricter profiles.

**Affected resources:** kv-e2e-rbac/Namespace/kv-e2e-rbac

</details>

<details>
<summary>Remediation: ephemeral-storage-limits (2 resources affected)</summary>

## Why This Matters

Ephemeral storage includes container logs, emptyDir volumes, and the writable container layer. Without limits, a single container can fill the node's root disk, triggering eviction of all pods on that node and potentially causing a cascading failure across your cluster. This is a common denial-of-service vector.

## How to Fix

Set ephemeral-storage limits alongside your CPU and memory limits:

```yaml
resources:
  limits:
    ephemeral-storage: 1Gi
  requests:
    ephemeral-storage: 500Mi
```

Estimate your application's disk usage from logs, temporary files, and cache data. If your application writes large temporary files, consider using a PersistentVolumeClaim instead of ephemeral storage.

## Learn More

The kubelet evicts pods that exceed their ephemeral-storage limit. Use LimitRange to set default ephemeral-storage limits at the namespace level to catch containers that omit this setting.

**Affected resources:** kv-e2e-rbac/Pod/kv-e2e-automount-pod, kv-e2e-rbac/Pod/kv-e2e-no-projection-pod

</details>

<details>
<summary>Remediation: image-no-digest (2 resources affected)</summary>

## Why This Matters

Image tags are mutable pointers -- a registry administrator or attacker can re-push a different image under the same tag. Without a digest, you have no cryptographic guarantee that the image you deploy is the one you tested.

## How to Fix

Pin images by their SHA-256 content digest for a fully immutable reference:

```yaml
containers:
  - name: app
    image: nginx@sha256:a8281ce420348a01ea6e   # Immutable
```

Use `crane digest nginx:1.25.3` or `skopeo inspect` to resolve a tag to its digest during CI/CD, then commit the pinned reference.

## Learn More

SLSA Level 1+ and NIST SP 800-190 recommend digest pinning for container supply chain integrity. See the Kubernetes images documentation for details.

**Affected resources:** kv-e2e-rbac/Pod/kv-e2e-automount-pod, kv-e2e-rbac/Pod/kv-e2e-no-projection-pod

</details>

<details>
<summary>Remediation: liveness-readiness-probes (4 resources affected)</summary>

## Why This Matters

Without a liveness probe, Kubernetes cannot detect when a container has become unresponsive or deadlocked. The container continues running and consuming resources while failing to serve traffic. Users experience timeouts and errors until someone manually intervenes.

## How to Fix

Add a liveness probe that checks the container's health:

```yaml
containers:
  - name: app
    livenessProbe:
      httpGet:
        path: /healthz
        port: 8080
      initialDelaySeconds: 15
      periodSeconds: 10
      failureThreshold: 3
```

Use `httpGet` for HTTP services, `tcpSocket` for TCP services, or `exec` with a custom health check script for non-network workloads.

## Learn More

See the Kubernetes documentation on container probes. Set initialDelaySeconds high enough for your application to start, and consider adding a startupProbe for slow-starting containers.

**Affected resources:** kv-e2e-rbac/Pod/kv-e2e-automount-pod, kv-e2e-rbac/Pod/kv-e2e-automount-pod, kv-e2e-rbac/Pod/kv-e2e-no-projection-pod, kv-e2e-rbac/Pod/kv-e2e-no-projection-pod

</details>

<details>
<summary>Remediation: priority-class-missing (2 resources affected)</summary>

## Why This Matters

Without a PriorityClass, pods receive default priority (typically 0) and are among the first to be evicted during resource pressure or node maintenance. This means important application workloads may be killed before less critical ones, leading to unpredictable outages.

## How to Fix

Define PriorityClasses for your workloads and assign them appropriately:

```yaml
apiVersion: scheduling.k8s.io/v1
kind: PriorityClass
metadata:
  name: app-medium
value: 100000
---
# Reference in your workload:
spec:
  priorityClassName: app-medium
```

Create a tiered priority scheme (e.g., app-critical: 500000, app-medium: 100000, app-low: 10000) that reflects your workload importance hierarchy.

## Learn More

Refer to the Kubernetes Pod Priority and Preemption documentation. Establishing a consistent priority scheme across namespaces ensures predictable eviction behavior during resource contention.

**Affected resources:** kv-e2e-rbac/Pod/kv-e2e-automount-pod, kv-e2e-rbac/Pod/kv-e2e-no-projection-pod

</details>

<details>
<summary>Remediation: runtime-class (2 resources affected)</summary>

## Why This Matters

Without a RuntimeClass, pods use the default container runtime (typically runc), which shares the host kernel directly with containers. A kernel vulnerability can allow container escape to the host. Sandboxed runtimes like gVisor or Kata Containers add an additional isolation layer that intercepts system calls or runs containers in lightweight VMs.

## How to Fix

Specify a sandboxed RuntimeClass in the pod spec:

```yaml
spec:
  runtimeClassName: gvisor
```

Available RuntimeClasses depend on your cluster configuration. Common options include `gvisor` (user-space kernel), `kata` (micro-VMs), and `firecracker`. Check your cluster's available RuntimeClasses with `kubectl get runtimeclasses`.

## Learn More

Sandboxed runtimes are especially important for multi-tenant clusters and workloads processing untrusted input. They add latency overhead, so evaluate performance requirements. See the Kubernetes RuntimeClass documentation.

**Affected resources:** kv-e2e-rbac/Pod/kv-e2e-automount-pod, kv-e2e-rbac/Pod/kv-e2e-no-projection-pod

</details>

<details>
<summary>Remediation: topology-spread (2 resources affected)</summary>

## Why This Matters

Without topology spread constraints, the scheduler may place all replicas on the same node or in the same availability zone. If that node or zone fails, your entire service goes down despite having multiple replicas. This negates the high-availability benefits of running multiple pods.

## How to Fix

Add topology spread constraints to distribute replicas across failure domains:

```yaml
spec:
  topologySpreadConstraints:
    - maxSkew: 1
      topologyKey: kubernetes.io/hostname
      whenUnsatisfiable: DoNotSchedule
      labelSelector:
        matchLabels:
          app: my-app
    - maxSkew: 1
      topologyKey: topology.kubernetes.io/zone
      whenUnsatisfiable: ScheduleAnyway
```

Use `kubernetes.io/hostname` for node-level spreading and `topology.kubernetes.io/zone` for zone-level spreading.

## Learn More

See the Kubernetes Pod Topology Spread Constraints documentation. Combining hostname and zone constraints provides both node-level and zone-level fault tolerance.

**Affected resources:** kv-e2e-rbac/Pod/kv-e2e-automount-pod, kv-e2e-rbac/Pod/kv-e2e-no-projection-pod

</details>

<details>
<summary>Remediation: limit-range-missing (1 resources affected)</summary>

## Why This Matters

Without a LimitRange, any container can be created without resource constraints. A single runaway or malicious pod can consume all node CPU and memory, causing denial of service for other workloads on the same node.

## How to Fix

Create a LimitRange in the namespace to set default and maximum resource constraints:

```yaml
apiVersion: v1
kind: LimitRange
metadata:
  name: default-limits
  namespace: my-app
spec:
  limits:
    - type: Container
      default:
        cpu: 500m
        memory: 256Mi
      defaultRequest:
        cpu: 100m
        memory: 128Mi
      max:
        cpu: "2"
        memory: 1Gi
```

Containers that omit resource requests/limits will inherit these defaults automatically.

## Learn More

CIS Kubernetes Benchmark 5.2.1 recommends LimitRanges for resource governance. See https://kubernetes.io/docs/concepts/policy/limit-range/ for configuration details.

**Affected resources:** kv-e2e-rbac/Namespace/kv-e2e-rbac

</details>

<details>
<summary>Remediation: resource-quota-missing (1 resources affected)</summary>

## Why This Matters

Without a ResourceQuota, a single namespace can consume the entire cluster's CPU, memory, and storage. This creates a noisy-neighbor problem where one team's workloads starve others, and makes capacity planning impossible.

## How to Fix

Create a ResourceQuota to cap the namespace's total resource consumption:

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: compute-quota
  namespace: my-app
spec:
  hard:
    requests.cpu: "10"
    requests.memory: 20Gi
    limits.cpu: "20"
    limits.memory: 40Gi
    pods: "50"
    services: "10"
```

Tune quota values based on the namespace's actual workload requirements and cluster capacity.

## Learn More

CIS Kubernetes Benchmark 5.2.2 recommends ResourceQuotas for multi-tenant clusters. See https://kubernetes.io/docs/concepts/policy/resource-quotas/ for quota configuration and enforcement behavior.

**Affected resources:** kv-e2e-rbac/Namespace/kv-e2e-rbac

</details>

<details>
<summary>Remediation: rbac-unused-roles (1 resources affected)</summary>

## Why This Matters

Unused Roles and ClusterRoles are dormant permissions waiting to be activated. An attacker who can create or modify RoleBindings could bind these unused roles to gain additional privileges. They also create confusion during audits and make it harder to understand the actual RBAC posture.

## How to Fix

Verify the role is truly unused, then remove it:

```bash
# Check for any bindings referencing this role
kubectl get rolebindings,clusterrolebindings -A \
  -o json | jq '.items[] | select(.roleRef.name=="unused-role")'

# Remove the unused role
kubectl delete clusterrole unused-role
kubectl delete role unused-role -n my-namespace
```

Implement a regular RBAC hygiene process to review and clean up unused roles quarterly.

## Learn More

See the Kubernetes RBAC best practices documentation and CIS Kubernetes Benchmark section 5.1 for guidance on maintaining a clean RBAC configuration.

**Affected resources:** kv-e2e-rbac/Role/kv-e2e-unused-role

</details>

### kv-e2e-scheduling (221 findings — 🟠40 🟡114 🔵67)

| Severity | Check | Resources | Message | Frameworks |
|----------|-------|-----------|---------|-----------|
| 🟠 High | automount-token | **9 resources** | Deployment "control-plane-tolerator" auto-mounts a ServiceAccount token. Most workloads do not need Kubernetes API access. | CIS 5.1.6 · MITRE T1552.007 · NSA 3.2 |
| 🟠 High | default-service-account | **9 resources** | Deployment "control-plane-tolerator" uses the default ServiceAccount, which may have unintended permissions. | CIS 5.1.5 · CIS 5.1.6 · MITRE T1078.001 · NSA 3.1 · NSA 3.2 |
| 🟠 High | privilege-escalation | **9 resources** | Container "pause" does not set allowPrivilegeEscalation to false, permitting privilege escalation. | CIS 5.2.6 · MITRE T1068 · MITRE T1611 · NSA 1.1 · NSA 2.1 |
| 🟠 High | run-as-root | **9 resources** | Container "pause" does not set runAsNonRoot: true and may run as root. | CIS 5.2.7 · MITRE T1611 · NSA 1.1 |
| 🟠 High | toleration-control-plane | **2 resources** | Deployment "control-plane-tolerator" tolerates control-plane taint key "node-role.kubernetes.io/control-plane"; only system components should run on control-plane nodes. | CIS 5.6.3 · MITRE T1611 · NSA 1.3 |
| 🟠 High | network-policy-missing | kv-e2e-scheduling/Namespace/kv-e2e-scheduling | Namespace "kv-e2e-scheduling" has no NetworkPolicy defined. All pods are unrestricted. | CIS 5.3.2 · MITRE T1046 · NSA 4.1 · NSA 4.2 |
| 🟠 High | priority-class-system | kv-e2e-scheduling/Deployment/system-priority-app | Deployment "system-priority-app" uses system PriorityClass "system-cluster-critical" which can preempt legitimate system pods. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🟡 Medium | apparmor-profile | **9 resources** | Container "pause" does not have an AppArmor profile set. | CIS 5.6.3 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | capabilities-not-dropped | **9 resources** | Container "pause" does not drop ALL capabilities, leaving it with unnecessary default privileges. | CIS 5.2.8 · CIS 5.2.10 · MITRE T1068 · NSA 1.1 |
| 🟡 Medium | image-pull-policy | **9 resources** | Container "pause" uses a mutable image tag with pullPolicy "IfNotPresent" (image: registry.k8s.io/pause:3.9), risking stale images. | CIS 5.5.1 · MITRE T1525 · NSA 1.4 |
| 🟡 Medium | psa-restricted-violations | **27 resources** | Deployment "control-plane-tolerator" container "pause" violates PSS Restricted: runAsNonRoot is not true. | CIS 5.2.1 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | read-only-rootfs | **9 resources** | Container "pause" does not have a read-only root filesystem. | CIS 5.6.3 · MITRE T1565.001 · NSA 1.2 |
| 🟡 Medium | resource-limits-missing | **9 resources** | Container "pause" is missing both CPU and memory limits. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🟡 Medium | resource-requests-missing | **9 resources** | Container "pause" is missing both CPU and memory requests. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🟡 Medium | run-as-group | **9 resources** | Container "pause" does not set runAsGroup; the process will run as GID 0 (root group) by default. | CIS 5.2.7 · MITRE T1068 · NSA 1.1 |
| 🟡 Medium | seccomp-profile | **9 resources** | Container "pause" does not have a Seccomp profile set at either the container or pod level. | CIS 5.6.2 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | token-projection-config | **9 resources** | Deployment "control-plane-tolerator" does not use explicitly configured projected ServiceAccount tokens with expiry and audience restrictions. | CIS 5.1.6 · MITRE T1552.007 · NSA 3.2 |
| 🟡 Medium | hpa-without-requests | kv-e2e-scheduling/HorizontalPodAutoscaler/hpa-no-requests | HPA "hpa-no-requests" targets Deployment "hpa-target-no-requests" which has no resource requests set; percentage-based autoscaling will be unpredictable. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🟡 Medium | network-policy-egress-unrestricted | kv-e2e-scheduling/Namespace/kv-e2e-scheduling | Namespace "kv-e2e-scheduling" has no NetworkPolicy with egress restrictions. Pods can reach any external destination. | CIS 5.3.2 · MITRE T1048 · NSA 4.2 |
| 🟡 Medium | psa-labels-missing | kv-e2e-scheduling/Namespace/kv-e2e-scheduling | Namespace "kv-e2e-scheduling" is missing the pod-security.kubernetes.io/enforce label; pod security is not enforced. | CIS 5.2.1 · MITRE T1610 · NSA 2.1 |
| 🟡 Medium | node-affinity-untrusted | **2 resources** | Deployment "preemptible-affinity-deploy" has nodeAffinity targeting potentially untrusted nodes via label key "kubernetes.azure.com/scalesetpriority". | CIS 5.6.3 · MITRE T1610 · NSA 1.3 |
| 🟡 Medium | toleration-all | kv-e2e-scheduling/Deployment/tolerate-everything | Deployment "tolerate-everything" has a catch-all toleration (operator: Exists, empty key) that matches all taints. | CIS 5.6.3 · MITRE T1610 · NSA 1.3 |
| 🔵 Low | ephemeral-storage-limits | **9 resources** | Container "pause" is missing ephemeral-storage limits. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | image-no-digest | **9 resources** | Container "pause" image is not pinned by digest (image: registry.k8s.io/pause:3.9), allowing tag mutation. | CIS 5.5.1 · MITRE T1525 · NSA 1.4 |
| 🔵 Low | liveness-readiness-probes | **18 resources** | Container "pause" has no liveness probe configured. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | priority-class-missing | **8 resources** | Deployment "control-plane-tolerator" has no PriorityClass set; it will be evicted first during resource pressure. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | runtime-class | **9 resources** | Pod "control-plane-tolerator" does not specify a RuntimeClass, using the default (unsandboxed) runtime. | CIS 5.6.3 · MITRE T1611 · NSA 2.1 |
| 🔵 Low | topology-spread | **9 resources** | Deployment "control-plane-tolerator" has no topology spread constraints; all replicas may be scheduled on the same node. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | pod-disruption-budget | **3 resources** | Deployment "hpa-target-no-requests" has 2 replicas but no matching PodDisruptionBudget; all replicas can be evicted simultaneously. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | limit-range-missing | kv-e2e-scheduling/Namespace/kv-e2e-scheduling | Namespace "kv-e2e-scheduling" has no LimitRange defined. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | resource-quota-missing | kv-e2e-scheduling/Namespace/kv-e2e-scheduling | Namespace "kv-e2e-scheduling" has no ResourceQuota defined. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |

<details>
<summary>automount-token: 9 affected resources</summary>

- `kv-e2e-scheduling/Deployment/control-plane-tolerator`
- `kv-e2e-scheduling/Deployment/hpa-target-no-requests`
- `kv-e2e-scheduling/Deployment/no-pdb-app`
- `kv-e2e-scheduling/Deployment/no-priority-app`
- `kv-e2e-scheduling/Deployment/no-topology-spread-app`
- `kv-e2e-scheduling/Deployment/preemptible-affinity-deploy`
- `kv-e2e-scheduling/Deployment/spot-selector-deploy`
- `kv-e2e-scheduling/Deployment/system-priority-app`
- `kv-e2e-scheduling/Deployment/tolerate-everything`

</details>

<details>
<summary>default-service-account: 9 affected resources</summary>

- `kv-e2e-scheduling/Deployment/control-plane-tolerator`
- `kv-e2e-scheduling/Deployment/hpa-target-no-requests`
- `kv-e2e-scheduling/Deployment/no-pdb-app`
- `kv-e2e-scheduling/Deployment/no-priority-app`
- `kv-e2e-scheduling/Deployment/no-topology-spread-app`
- `kv-e2e-scheduling/Deployment/preemptible-affinity-deploy`
- `kv-e2e-scheduling/Deployment/spot-selector-deploy`
- `kv-e2e-scheduling/Deployment/system-priority-app`
- `kv-e2e-scheduling/Deployment/tolerate-everything`

</details>

<details>
<summary>privilege-escalation: 9 affected resources</summary>

- `kv-e2e-scheduling/Deployment/control-plane-tolerator (pause)`
- `kv-e2e-scheduling/Deployment/hpa-target-no-requests (pause)`
- `kv-e2e-scheduling/Deployment/no-pdb-app (pause)`
- `kv-e2e-scheduling/Deployment/no-priority-app (pause)`
- `kv-e2e-scheduling/Deployment/no-topology-spread-app (pause)`
- `kv-e2e-scheduling/Deployment/preemptible-affinity-deploy (pause)`
- `kv-e2e-scheduling/Deployment/spot-selector-deploy (pause)`
- `kv-e2e-scheduling/Deployment/system-priority-app (pause)`
- `kv-e2e-scheduling/Deployment/tolerate-everything (pause)`

</details>

<details>
<summary>run-as-root: 9 affected resources</summary>

- `kv-e2e-scheduling/Deployment/control-plane-tolerator (pause)`
- `kv-e2e-scheduling/Deployment/hpa-target-no-requests (pause)`
- `kv-e2e-scheduling/Deployment/no-pdb-app (pause)`
- `kv-e2e-scheduling/Deployment/no-priority-app (pause)`
- `kv-e2e-scheduling/Deployment/no-topology-spread-app (pause)`
- `kv-e2e-scheduling/Deployment/preemptible-affinity-deploy (pause)`
- `kv-e2e-scheduling/Deployment/spot-selector-deploy (pause)`
- `kv-e2e-scheduling/Deployment/system-priority-app (pause)`
- `kv-e2e-scheduling/Deployment/tolerate-everything (pause)`

</details>

<details>
<summary>toleration-control-plane: 2 affected resources</summary>

- `kv-e2e-scheduling/Deployment/control-plane-tolerator`
- `kv-e2e-scheduling/Deployment/control-plane-tolerator`

</details>

<details>
<summary>apparmor-profile: 9 affected resources</summary>

- `kv-e2e-scheduling/Deployment/control-plane-tolerator (pause)`
- `kv-e2e-scheduling/Deployment/hpa-target-no-requests (pause)`
- `kv-e2e-scheduling/Deployment/no-pdb-app (pause)`
- `kv-e2e-scheduling/Deployment/no-priority-app (pause)`
- `kv-e2e-scheduling/Deployment/no-topology-spread-app (pause)`
- `kv-e2e-scheduling/Deployment/preemptible-affinity-deploy (pause)`
- `kv-e2e-scheduling/Deployment/spot-selector-deploy (pause)`
- `kv-e2e-scheduling/Deployment/system-priority-app (pause)`
- `kv-e2e-scheduling/Deployment/tolerate-everything (pause)`

</details>

<details>
<summary>capabilities-not-dropped: 9 affected resources</summary>

- `kv-e2e-scheduling/Deployment/control-plane-tolerator (pause)`
- `kv-e2e-scheduling/Deployment/hpa-target-no-requests (pause)`
- `kv-e2e-scheduling/Deployment/no-pdb-app (pause)`
- `kv-e2e-scheduling/Deployment/no-priority-app (pause)`
- `kv-e2e-scheduling/Deployment/no-topology-spread-app (pause)`
- `kv-e2e-scheduling/Deployment/preemptible-affinity-deploy (pause)`
- `kv-e2e-scheduling/Deployment/spot-selector-deploy (pause)`
- `kv-e2e-scheduling/Deployment/system-priority-app (pause)`
- `kv-e2e-scheduling/Deployment/tolerate-everything (pause)`

</details>

<details>
<summary>image-pull-policy: 9 affected resources</summary>

- `kv-e2e-scheduling/Deployment/control-plane-tolerator (pause)`
- `kv-e2e-scheduling/Deployment/hpa-target-no-requests (pause)`
- `kv-e2e-scheduling/Deployment/no-pdb-app (pause)`
- `kv-e2e-scheduling/Deployment/no-priority-app (pause)`
- `kv-e2e-scheduling/Deployment/no-topology-spread-app (pause)`
- `kv-e2e-scheduling/Deployment/preemptible-affinity-deploy (pause)`
- `kv-e2e-scheduling/Deployment/spot-selector-deploy (pause)`
- `kv-e2e-scheduling/Deployment/system-priority-app (pause)`
- `kv-e2e-scheduling/Deployment/tolerate-everything (pause)`

</details>

<details>
<summary>psa-restricted-violations: 27 affected resources</summary>

- `kv-e2e-scheduling/Deployment/control-plane-tolerator (pause)`
- `kv-e2e-scheduling/Deployment/control-plane-tolerator (pause)`
- `kv-e2e-scheduling/Deployment/control-plane-tolerator (pause)`
- `kv-e2e-scheduling/Deployment/hpa-target-no-requests (pause)`
- `kv-e2e-scheduling/Deployment/hpa-target-no-requests (pause)`
- `kv-e2e-scheduling/Deployment/hpa-target-no-requests (pause)`
- `kv-e2e-scheduling/Deployment/no-pdb-app (pause)`
- `kv-e2e-scheduling/Deployment/no-pdb-app (pause)`
- `kv-e2e-scheduling/Deployment/no-pdb-app (pause)`
- `kv-e2e-scheduling/Deployment/no-priority-app (pause)`
- `kv-e2e-scheduling/Deployment/no-priority-app (pause)`
- `kv-e2e-scheduling/Deployment/no-priority-app (pause)`
- `kv-e2e-scheduling/Deployment/no-topology-spread-app (pause)`
- `kv-e2e-scheduling/Deployment/no-topology-spread-app (pause)`
- `kv-e2e-scheduling/Deployment/no-topology-spread-app (pause)`
- `kv-e2e-scheduling/Deployment/preemptible-affinity-deploy (pause)`
- `kv-e2e-scheduling/Deployment/preemptible-affinity-deploy (pause)`
- `kv-e2e-scheduling/Deployment/preemptible-affinity-deploy (pause)`
- `kv-e2e-scheduling/Deployment/spot-selector-deploy (pause)`
- `kv-e2e-scheduling/Deployment/spot-selector-deploy (pause)`
- `kv-e2e-scheduling/Deployment/spot-selector-deploy (pause)`
- `kv-e2e-scheduling/Deployment/system-priority-app (pause)`
- `kv-e2e-scheduling/Deployment/system-priority-app (pause)`
- `kv-e2e-scheduling/Deployment/system-priority-app (pause)`
- `kv-e2e-scheduling/Deployment/tolerate-everything (pause)`
- `kv-e2e-scheduling/Deployment/tolerate-everything (pause)`
- `kv-e2e-scheduling/Deployment/tolerate-everything (pause)`

</details>

<details>
<summary>read-only-rootfs: 9 affected resources</summary>

- `kv-e2e-scheduling/Deployment/control-plane-tolerator (pause)`
- `kv-e2e-scheduling/Deployment/hpa-target-no-requests (pause)`
- `kv-e2e-scheduling/Deployment/no-pdb-app (pause)`
- `kv-e2e-scheduling/Deployment/no-priority-app (pause)`
- `kv-e2e-scheduling/Deployment/no-topology-spread-app (pause)`
- `kv-e2e-scheduling/Deployment/preemptible-affinity-deploy (pause)`
- `kv-e2e-scheduling/Deployment/spot-selector-deploy (pause)`
- `kv-e2e-scheduling/Deployment/system-priority-app (pause)`
- `kv-e2e-scheduling/Deployment/tolerate-everything (pause)`

</details>

<details>
<summary>resource-limits-missing: 9 affected resources</summary>

- `kv-e2e-scheduling/Deployment/control-plane-tolerator (pause)`
- `kv-e2e-scheduling/Deployment/hpa-target-no-requests (pause)`
- `kv-e2e-scheduling/Deployment/no-pdb-app (pause)`
- `kv-e2e-scheduling/Deployment/no-priority-app (pause)`
- `kv-e2e-scheduling/Deployment/no-topology-spread-app (pause)`
- `kv-e2e-scheduling/Deployment/preemptible-affinity-deploy (pause)`
- `kv-e2e-scheduling/Deployment/spot-selector-deploy (pause)`
- `kv-e2e-scheduling/Deployment/system-priority-app (pause)`
- `kv-e2e-scheduling/Deployment/tolerate-everything (pause)`

</details>

<details>
<summary>resource-requests-missing: 9 affected resources</summary>

- `kv-e2e-scheduling/Deployment/control-plane-tolerator (pause)`
- `kv-e2e-scheduling/Deployment/hpa-target-no-requests (pause)`
- `kv-e2e-scheduling/Deployment/no-pdb-app (pause)`
- `kv-e2e-scheduling/Deployment/no-priority-app (pause)`
- `kv-e2e-scheduling/Deployment/no-topology-spread-app (pause)`
- `kv-e2e-scheduling/Deployment/preemptible-affinity-deploy (pause)`
- `kv-e2e-scheduling/Deployment/spot-selector-deploy (pause)`
- `kv-e2e-scheduling/Deployment/system-priority-app (pause)`
- `kv-e2e-scheduling/Deployment/tolerate-everything (pause)`

</details>

<details>
<summary>run-as-group: 9 affected resources</summary>

- `kv-e2e-scheduling/Deployment/control-plane-tolerator (pause)`
- `kv-e2e-scheduling/Deployment/hpa-target-no-requests (pause)`
- `kv-e2e-scheduling/Deployment/no-pdb-app (pause)`
- `kv-e2e-scheduling/Deployment/no-priority-app (pause)`
- `kv-e2e-scheduling/Deployment/no-topology-spread-app (pause)`
- `kv-e2e-scheduling/Deployment/preemptible-affinity-deploy (pause)`
- `kv-e2e-scheduling/Deployment/spot-selector-deploy (pause)`
- `kv-e2e-scheduling/Deployment/system-priority-app (pause)`
- `kv-e2e-scheduling/Deployment/tolerate-everything (pause)`

</details>

<details>
<summary>seccomp-profile: 9 affected resources</summary>

- `kv-e2e-scheduling/Deployment/control-plane-tolerator (pause)`
- `kv-e2e-scheduling/Deployment/hpa-target-no-requests (pause)`
- `kv-e2e-scheduling/Deployment/no-pdb-app (pause)`
- `kv-e2e-scheduling/Deployment/no-priority-app (pause)`
- `kv-e2e-scheduling/Deployment/no-topology-spread-app (pause)`
- `kv-e2e-scheduling/Deployment/preemptible-affinity-deploy (pause)`
- `kv-e2e-scheduling/Deployment/spot-selector-deploy (pause)`
- `kv-e2e-scheduling/Deployment/system-priority-app (pause)`
- `kv-e2e-scheduling/Deployment/tolerate-everything (pause)`

</details>

<details>
<summary>token-projection-config: 9 affected resources</summary>

- `kv-e2e-scheduling/Deployment/control-plane-tolerator`
- `kv-e2e-scheduling/Deployment/hpa-target-no-requests`
- `kv-e2e-scheduling/Deployment/no-pdb-app`
- `kv-e2e-scheduling/Deployment/no-priority-app`
- `kv-e2e-scheduling/Deployment/no-topology-spread-app`
- `kv-e2e-scheduling/Deployment/preemptible-affinity-deploy`
- `kv-e2e-scheduling/Deployment/spot-selector-deploy`
- `kv-e2e-scheduling/Deployment/system-priority-app`
- `kv-e2e-scheduling/Deployment/tolerate-everything`

</details>

<details>
<summary>node-affinity-untrusted: 2 affected resources</summary>

- `kv-e2e-scheduling/Deployment/preemptible-affinity-deploy`
- `kv-e2e-scheduling/Deployment/spot-selector-deploy`

</details>

<details>
<summary>ephemeral-storage-limits: 9 affected resources</summary>

- `kv-e2e-scheduling/Deployment/control-plane-tolerator (pause)`
- `kv-e2e-scheduling/Deployment/hpa-target-no-requests (pause)`
- `kv-e2e-scheduling/Deployment/no-pdb-app (pause)`
- `kv-e2e-scheduling/Deployment/no-priority-app (pause)`
- `kv-e2e-scheduling/Deployment/no-topology-spread-app (pause)`
- `kv-e2e-scheduling/Deployment/preemptible-affinity-deploy (pause)`
- `kv-e2e-scheduling/Deployment/spot-selector-deploy (pause)`
- `kv-e2e-scheduling/Deployment/system-priority-app (pause)`
- `kv-e2e-scheduling/Deployment/tolerate-everything (pause)`

</details>

<details>
<summary>image-no-digest: 9 affected resources</summary>

- `kv-e2e-scheduling/Deployment/control-plane-tolerator (pause)`
- `kv-e2e-scheduling/Deployment/hpa-target-no-requests (pause)`
- `kv-e2e-scheduling/Deployment/no-pdb-app (pause)`
- `kv-e2e-scheduling/Deployment/no-priority-app (pause)`
- `kv-e2e-scheduling/Deployment/no-topology-spread-app (pause)`
- `kv-e2e-scheduling/Deployment/preemptible-affinity-deploy (pause)`
- `kv-e2e-scheduling/Deployment/spot-selector-deploy (pause)`
- `kv-e2e-scheduling/Deployment/system-priority-app (pause)`
- `kv-e2e-scheduling/Deployment/tolerate-everything (pause)`

</details>

<details>
<summary>liveness-readiness-probes: 18 affected resources</summary>

- `kv-e2e-scheduling/Deployment/control-plane-tolerator (pause)`
- `kv-e2e-scheduling/Deployment/control-plane-tolerator (pause)`
- `kv-e2e-scheduling/Deployment/hpa-target-no-requests (pause)`
- `kv-e2e-scheduling/Deployment/hpa-target-no-requests (pause)`
- `kv-e2e-scheduling/Deployment/no-pdb-app (pause)`
- `kv-e2e-scheduling/Deployment/no-pdb-app (pause)`
- `kv-e2e-scheduling/Deployment/no-priority-app (pause)`
- `kv-e2e-scheduling/Deployment/no-priority-app (pause)`
- `kv-e2e-scheduling/Deployment/no-topology-spread-app (pause)`
- `kv-e2e-scheduling/Deployment/no-topology-spread-app (pause)`
- `kv-e2e-scheduling/Deployment/preemptible-affinity-deploy (pause)`
- `kv-e2e-scheduling/Deployment/preemptible-affinity-deploy (pause)`
- `kv-e2e-scheduling/Deployment/spot-selector-deploy (pause)`
- `kv-e2e-scheduling/Deployment/spot-selector-deploy (pause)`
- `kv-e2e-scheduling/Deployment/system-priority-app (pause)`
- `kv-e2e-scheduling/Deployment/system-priority-app (pause)`
- `kv-e2e-scheduling/Deployment/tolerate-everything (pause)`
- `kv-e2e-scheduling/Deployment/tolerate-everything (pause)`

</details>

<details>
<summary>priority-class-missing: 8 affected resources</summary>

- `kv-e2e-scheduling/Deployment/control-plane-tolerator`
- `kv-e2e-scheduling/Deployment/hpa-target-no-requests`
- `kv-e2e-scheduling/Deployment/no-pdb-app`
- `kv-e2e-scheduling/Deployment/no-priority-app`
- `kv-e2e-scheduling/Deployment/no-topology-spread-app`
- `kv-e2e-scheduling/Deployment/preemptible-affinity-deploy`
- `kv-e2e-scheduling/Deployment/spot-selector-deploy`
- `kv-e2e-scheduling/Deployment/tolerate-everything`

</details>

<details>
<summary>runtime-class: 9 affected resources</summary>

- `kv-e2e-scheduling/Deployment/control-plane-tolerator`
- `kv-e2e-scheduling/Deployment/hpa-target-no-requests`
- `kv-e2e-scheduling/Deployment/no-pdb-app`
- `kv-e2e-scheduling/Deployment/no-priority-app`
- `kv-e2e-scheduling/Deployment/no-topology-spread-app`
- `kv-e2e-scheduling/Deployment/preemptible-affinity-deploy`
- `kv-e2e-scheduling/Deployment/spot-selector-deploy`
- `kv-e2e-scheduling/Deployment/system-priority-app`
- `kv-e2e-scheduling/Deployment/tolerate-everything`

</details>

<details>
<summary>topology-spread: 9 affected resources</summary>

- `kv-e2e-scheduling/Deployment/control-plane-tolerator`
- `kv-e2e-scheduling/Deployment/hpa-target-no-requests`
- `kv-e2e-scheduling/Deployment/no-pdb-app`
- `kv-e2e-scheduling/Deployment/no-priority-app`
- `kv-e2e-scheduling/Deployment/no-topology-spread-app`
- `kv-e2e-scheduling/Deployment/preemptible-affinity-deploy`
- `kv-e2e-scheduling/Deployment/spot-selector-deploy`
- `kv-e2e-scheduling/Deployment/system-priority-app`
- `kv-e2e-scheduling/Deployment/tolerate-everything`

</details>

<details>
<summary>pod-disruption-budget: 3 affected resources</summary>

- `kv-e2e-scheduling/Deployment/hpa-target-no-requests`
- `kv-e2e-scheduling/Deployment/no-pdb-app`
- `kv-e2e-scheduling/Deployment/no-topology-spread-app`

</details>

<details>
<summary>Remediation: automount-token (9 resources affected)</summary>

## Why This Matters

When a ServiceAccount token is auto-mounted, every container in the pod can call the Kubernetes API. If a container is compromised through a vulnerability or misconfiguration, the attacker gains API access to enumerate resources, read secrets, or escalate privileges.

## How to Fix

Disable auto-mounting at the pod spec level for workloads that do not need API access:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      automountServiceAccountToken: false
      containers:
        - name: app
          image: my-app:latest
```

For workloads that do require API access, use projected tokens with bounded lifetime and audience restrictions instead of the default long-lived token.

## Learn More

Refer to the Kubernetes documentation on configuring service accounts for pods and CIS Kubernetes Benchmark 5.1.6 for auto-mount token guidance.

**Affected resources:** kv-e2e-scheduling/Deployment/control-plane-tolerator, kv-e2e-scheduling/Deployment/hpa-target-no-requests, kv-e2e-scheduling/Deployment/no-pdb-app, kv-e2e-scheduling/Deployment/no-priority-app, kv-e2e-scheduling/Deployment/no-topology-spread-app, kv-e2e-scheduling/Deployment/preemptible-affinity-deploy, kv-e2e-scheduling/Deployment/spot-selector-deploy, kv-e2e-scheduling/Deployment/system-priority-app, kv-e2e-scheduling/Deployment/tolerate-everything

</details>

<details>
<summary>Remediation: default-service-account (9 resources affected)</summary>

## Why This Matters

The default ServiceAccount is shared by every pod in a namespace. If any pod is compromised, the attacker inherits whatever permissions have been granted to the default account via role bindings, enabling lateral movement across all workloads sharing it.

## How to Fix

Create a dedicated ServiceAccount for each workload and reference it in the pod spec:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-app
  namespace: production
automountServiceAccountToken: false
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      serviceAccountName: my-app
```

Grant only the permissions the workload actually needs via a dedicated Role and RoleBinding.

## Learn More

See the Kubernetes documentation on managing service accounts and CIS Kubernetes Benchmark 5.1.5 for guidance on ensuring default service accounts are not actively used.

**Affected resources:** kv-e2e-scheduling/Deployment/control-plane-tolerator, kv-e2e-scheduling/Deployment/hpa-target-no-requests, kv-e2e-scheduling/Deployment/no-pdb-app, kv-e2e-scheduling/Deployment/no-priority-app, kv-e2e-scheduling/Deployment/no-topology-spread-app, kv-e2e-scheduling/Deployment/preemptible-affinity-deploy, kv-e2e-scheduling/Deployment/spot-selector-deploy, kv-e2e-scheduling/Deployment/system-priority-app, kv-e2e-scheduling/Deployment/tolerate-everything

</details>

<details>
<summary>Remediation: privilege-escalation (9 resources affected)</summary>

## Why This Matters

By default, Kubernetes allows containers to escalate privileges via setuid/setgid binaries, which let a process gain more permissions than its parent. An attacker can exploit this using setuid binaries already present in the container image (like `su`, `sudo`, or `ping`) to elevate from a low-privilege user to root.

## How to Fix

Explicitly disable privilege escalation in the container's securityContext:

```yaml
securityContext:
  allowPrivilegeEscalation: false
  runAsNonRoot: true
  capabilities:
    drop: ["ALL"]
```

This blocks the use of setuid/setgid binaries and prevents the no_new_privs Linux flag from being cleared. The vast majority of application containers do not need privilege escalation.

## Learn More

This is required by the Pod Security Standards "Restricted" profile and CIS Benchmark 5.2.5. Disabling privilege escalation is one of the most impactful single-line security improvements you can make.

**Affected resources:** kv-e2e-scheduling/Deployment/control-plane-tolerator, kv-e2e-scheduling/Deployment/hpa-target-no-requests, kv-e2e-scheduling/Deployment/no-pdb-app, kv-e2e-scheduling/Deployment/no-priority-app, kv-e2e-scheduling/Deployment/no-topology-spread-app, kv-e2e-scheduling/Deployment/preemptible-affinity-deploy, kv-e2e-scheduling/Deployment/spot-selector-deploy, kv-e2e-scheduling/Deployment/system-priority-app, kv-e2e-scheduling/Deployment/tolerate-everything

</details>

<details>
<summary>Remediation: run-as-root (9 resources affected)</summary>

## Why This Matters

Without `runAsNonRoot: true`, Kubernetes does not enforce non-root execution and the container may default to running as UID 0 depending on the image's USER directive. If the image defaults to root, the container process gains full privileges, increasing the blast radius of any compromise or container escape.

## How to Fix

Enforce non-root execution in the securityContext:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
```

With `runAsNonRoot: true`, Kubernetes will reject the pod at admission time if the container image attempts to run as root. Setting an explicit `runAsUser` provides an additional guarantee.

## Learn More

This aligns with CIS Benchmark 5.2.6 and the Pod Security Standards "Restricted" profile. The `runAsNonRoot` field acts as a safety net even when images change their default USER.

**Affected resources:** kv-e2e-scheduling/Deployment/control-plane-tolerator, kv-e2e-scheduling/Deployment/hpa-target-no-requests, kv-e2e-scheduling/Deployment/no-pdb-app, kv-e2e-scheduling/Deployment/no-priority-app, kv-e2e-scheduling/Deployment/no-topology-spread-app, kv-e2e-scheduling/Deployment/preemptible-affinity-deploy, kv-e2e-scheduling/Deployment/spot-selector-deploy, kv-e2e-scheduling/Deployment/system-priority-app, kv-e2e-scheduling/Deployment/tolerate-everything

</details>

<details>
<summary>Remediation: toleration-control-plane (2 resources affected)</summary>

## Why This Matters

Control-plane nodes run critical cluster components like the API server, etcd, and scheduler. If a compromised workload runs on a control-plane node, an attacker can access these components directly, potentially gaining full cluster control or corrupting cluster state.

## How to Fix

Remove the control-plane toleration from your workload spec:

```yaml
spec:
  tolerations:
    # Remove these entries:
    # - key: node-role.kubernetes.io/control-plane
    #   effect: NoSchedule
    # - key: node-role.kubernetes.io/master
    #   effect: NoSchedule
    - key: dedicated
      operator: Equal
      value: my-team
      effect: NoSchedule
```

If the workload genuinely needs to run on control-plane nodes, deploy it in the kube-system namespace with minimal privileges.

## Learn More

The CIS Kubernetes Benchmark recommends isolating control-plane nodes from tenant workloads. See the Kubernetes documentation on taints and tolerations for scheduling best practices.

**Affected resources:** kv-e2e-scheduling/Deployment/control-plane-tolerator, kv-e2e-scheduling/Deployment/control-plane-tolerator

</details>

<details>
<summary>Remediation: network-policy-missing (1 resources affected)</summary>

## Why This Matters

Without NetworkPolicies, every pod in this namespace can communicate freely with every other pod in the cluster. If an attacker compromises a single pod, they can move laterally to databases, internal APIs, and other sensitive services with no network-level barriers.

## How to Fix

Create a default-deny NetworkPolicy for the namespace, then add targeted allow rules for legitimate traffic:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: my-namespace
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
```

After applying the default-deny, create additional NetworkPolicy resources that whitelist only the specific ingress and egress flows your workloads require.

## Learn More

See the Kubernetes documentation on NetworkPolicies and CIS Kubernetes Benchmark 5.3.2. A CNI plugin that supports NetworkPolicy (Calico, Cilium, Weave Net) must be installed for policies to take effect.

**Affected resources:** kv-e2e-scheduling/Namespace/kv-e2e-scheduling

</details>

<details>
<summary>Remediation: priority-class-system (1 resources affected)</summary>

## Why This Matters

The system-cluster-critical and system-node-critical PriorityClasses are reserved for essential cluster infrastructure like CoreDNS, kube-proxy, and CNI plugins. When application workloads use these classes, they can preempt real system components, causing DNS failures, networking outages, or even cluster instability.

## How to Fix

Create and use a custom PriorityClass with a value below system-critical thresholds:

```yaml
apiVersion: scheduling.k8s.io/v1
kind: PriorityClass
metadata:
  name: app-high-priority
value: 1000000
preemptionPolicy: PreemptLowerPriority
globalDefault: false
---
# Then reference it in your workload:
spec:
  priorityClassName: app-high-priority
```

System priority values start at 2000000000. Keep application priorities well below this threshold.

## Learn More

See the Kubernetes Pod Priority and Preemption documentation for guidance on defining PriorityClasses. The CIS Benchmark recommends restricting system priority classes to kube-system namespace only.

**Affected resources:** kv-e2e-scheduling/Deployment/system-priority-app

</details>

<details>
<summary>Remediation: apparmor-profile (9 resources affected)</summary>

## Why This Matters

AppArmor provides mandatory access control (MAC) that restricts which files, network resources, and capabilities a container process can access. Without an AppArmor profile, the container operates without these restrictions, allowing an attacker with code execution to access any file the container user can read and make unrestricted network connections.

## How to Fix

Apply an AppArmor profile in the container's securityContext (Kubernetes 1.30+):

```yaml
securityContext:
  appArmorProfile:
    type: RuntimeDefault
```

The RuntimeDefault profile provides sensible restrictions for most applications. For tighter control, create a custom Localhost profile that only allows the specific file and network access your application needs.

## Learn More

AppArmor is available on Debian/Ubuntu-based nodes. RHEL/CentOS nodes use SELinux instead. Both provide MAC enforcement. Refer to CIS Benchmark 5.7.5 and the Kubernetes AppArmor documentation.

**Affected resources:** kv-e2e-scheduling/Deployment/control-plane-tolerator, kv-e2e-scheduling/Deployment/hpa-target-no-requests, kv-e2e-scheduling/Deployment/no-pdb-app, kv-e2e-scheduling/Deployment/no-priority-app, kv-e2e-scheduling/Deployment/no-topology-spread-app, kv-e2e-scheduling/Deployment/preemptible-affinity-deploy, kv-e2e-scheduling/Deployment/spot-selector-deploy, kv-e2e-scheduling/Deployment/system-priority-app, kv-e2e-scheduling/Deployment/tolerate-everything

</details>

<details>
<summary>Remediation: capabilities-not-dropped (9 resources affected)</summary>

## Why This Matters

By default, containers receive a set of Linux capabilities including KILL, SETUID, SETGID, and NET_RAW. These defaults are rarely needed by application code and significantly increase the potential damage from a container compromise. Dropping all capabilities follows the principle of least privilege.

## How to Fix

Explicitly drop all capabilities and selectively add back only what your application needs:

```yaml
securityContext:
  capabilities:
    drop: ["ALL"]
    add: ["NET_BIND_SERVICE"]  # Only if needed
```

Most web applications, API servers, and background workers run perfectly with all capabilities dropped. Test your application after making this change to confirm no functionality is lost.

## Learn More

This is required by the Pod Security Standards "Restricted" profile and aligns with CIS Benchmark 5.2.7. Kubernetes best practice is to treat capability grants as exceptions that require explicit justification.

**Affected resources:** kv-e2e-scheduling/Deployment/control-plane-tolerator, kv-e2e-scheduling/Deployment/hpa-target-no-requests, kv-e2e-scheduling/Deployment/no-pdb-app, kv-e2e-scheduling/Deployment/no-priority-app, kv-e2e-scheduling/Deployment/no-topology-spread-app, kv-e2e-scheduling/Deployment/preemptible-affinity-deploy, kv-e2e-scheduling/Deployment/spot-selector-deploy, kv-e2e-scheduling/Deployment/system-priority-app, kv-e2e-scheduling/Deployment/tolerate-everything

</details>

<details>
<summary>Remediation: image-pull-policy (9 resources affected)</summary>

## Why This Matters

When a mutable image tag is used without `imagePullPolicy: Always`, Kubernetes may serve a cached version of the image from the node. If the tag has been updated in the registry (with a security patch or -- worse -- a compromised layer), the running container will not reflect those changes.

## How to Fix

Set `imagePullPolicy: Always` for any container using a mutable tag:

```yaml
containers:
  - name: app
    image: nginx:1.25.3
    imagePullPolicy: Always   # Forces fresh pull each time
```

Alternatively, pin images by digest (`image@sha256:...`), which makes the pull policy irrelevant because the content is immutable.

## Learn More

See the Kubernetes documentation on image pull policies and CIS Kubernetes Benchmark 5.4.2 for pull policy guidance.

**Affected resources:** kv-e2e-scheduling/Deployment/control-plane-tolerator, kv-e2e-scheduling/Deployment/hpa-target-no-requests, kv-e2e-scheduling/Deployment/no-pdb-app, kv-e2e-scheduling/Deployment/no-priority-app, kv-e2e-scheduling/Deployment/no-topology-spread-app, kv-e2e-scheduling/Deployment/preemptible-affinity-deploy, kv-e2e-scheduling/Deployment/spot-selector-deploy, kv-e2e-scheduling/Deployment/system-priority-app, kv-e2e-scheduling/Deployment/tolerate-everything

</details>

<details>
<summary>Remediation: psa-restricted-violations (27 resources affected)</summary>

## Why This Matters

Running as root inside a container means that any container escape vulnerability immediately grants root access on the host node. Even without an escape, root inside the container can modify sensitive files, install packages, and access capabilities that non-root users cannot.

## How to Fix

Set `runAsNonRoot: true` and specify a non-root user ID in the security context:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
```

Set this at the pod level to apply to all containers. Ensure your container image supports running as a non-root user (many official images do).

## Learn More

See the Pod Security Standards Restricted profile and CIS Kubernetes Benchmark 5.2.6. Running as non-root is a fundamental container security best practice.

**Affected resources:** kv-e2e-scheduling/Deployment/control-plane-tolerator, kv-e2e-scheduling/Deployment/control-plane-tolerator, kv-e2e-scheduling/Deployment/control-plane-tolerator, kv-e2e-scheduling/Deployment/hpa-target-no-requests, kv-e2e-scheduling/Deployment/hpa-target-no-requests, kv-e2e-scheduling/Deployment/hpa-target-no-requests, kv-e2e-scheduling/Deployment/no-pdb-app, kv-e2e-scheduling/Deployment/no-pdb-app, kv-e2e-scheduling/Deployment/no-pdb-app, kv-e2e-scheduling/Deployment/no-priority-app, kv-e2e-scheduling/Deployment/no-priority-app, kv-e2e-scheduling/Deployment/no-priority-app, kv-e2e-scheduling/Deployment/no-topology-spread-app, kv-e2e-scheduling/Deployment/no-topology-spread-app, kv-e2e-scheduling/Deployment/no-topology-spread-app, kv-e2e-scheduling/Deployment/preemptible-affinity-deploy, kv-e2e-scheduling/Deployment/preemptible-affinity-deploy, kv-e2e-scheduling/Deployment/preemptible-affinity-deploy, kv-e2e-scheduling/Deployment/spot-selector-deploy, kv-e2e-scheduling/Deployment/spot-selector-deploy, kv-e2e-scheduling/Deployment/spot-selector-deploy, kv-e2e-scheduling/Deployment/system-priority-app, kv-e2e-scheduling/Deployment/system-priority-app, kv-e2e-scheduling/Deployment/system-priority-app, kv-e2e-scheduling/Deployment/tolerate-everything, kv-e2e-scheduling/Deployment/tolerate-everything, kv-e2e-scheduling/Deployment/tolerate-everything

</details>

<details>
<summary>Remediation: read-only-rootfs (9 resources affected)</summary>

## Why This Matters

A writable root filesystem allows an attacker who gains code execution in your container to modify application binaries, install attack tools, plant backdoors, or persist malware across container restarts. Making the filesystem read-only eliminates an entire class of post-exploitation techniques.

## How to Fix

Enable a read-only root filesystem and mount writable volumes only where needed:

```yaml
securityContext:
  readOnlyRootFilesystem: true
volumeMounts:
  - name: tmp
    mountPath: /tmp
volumes:
  - name: tmp
    emptyDir: {}
```

Common paths that need write access include /tmp, /var/cache, and /var/run. Mount each as an emptyDir or tmpfs volume rather than making the entire filesystem writable.

## Learn More

This aligns with CIS Benchmark 5.2.4 and the defense-in-depth principle. Combined with dropping capabilities and running as non-root, a read-only filesystem forms a strong container hardening baseline.

**Affected resources:** kv-e2e-scheduling/Deployment/control-plane-tolerator, kv-e2e-scheduling/Deployment/hpa-target-no-requests, kv-e2e-scheduling/Deployment/no-pdb-app, kv-e2e-scheduling/Deployment/no-priority-app, kv-e2e-scheduling/Deployment/no-topology-spread-app, kv-e2e-scheduling/Deployment/preemptible-affinity-deploy, kv-e2e-scheduling/Deployment/spot-selector-deploy, kv-e2e-scheduling/Deployment/system-priority-app, kv-e2e-scheduling/Deployment/tolerate-everything

</details>

<details>
<summary>Remediation: resource-limits-missing (9 resources affected)</summary>

## Why This Matters

Without resource limits, a single container can consume all available CPU and memory on a node, starving other workloads and triggering cascading failures. An attacker who compromises an unlimited container can mount a denial-of-service attack against the entire node with a simple fork bomb or memory allocation loop.

## How to Fix

Set both CPU and memory limits based on your application's actual resource usage:

```yaml
resources:
  limits:
    cpu: 500m
    memory: 256Mi
  requests:
    cpu: 100m
    memory: 128Mi
```

Profile your application under load to determine appropriate values. Set limits to handle peak usage and requests to match steady-state consumption.

## Learn More

Use LimitRange objects to enforce default limits at the namespace level. Resource limits also determine the pod's QoS class: pods with equal requests and limits get Guaranteed QoS and are last to be evicted.

**Affected resources:** kv-e2e-scheduling/Deployment/control-plane-tolerator, kv-e2e-scheduling/Deployment/hpa-target-no-requests, kv-e2e-scheduling/Deployment/no-pdb-app, kv-e2e-scheduling/Deployment/no-priority-app, kv-e2e-scheduling/Deployment/no-topology-spread-app, kv-e2e-scheduling/Deployment/preemptible-affinity-deploy, kv-e2e-scheduling/Deployment/spot-selector-deploy, kv-e2e-scheduling/Deployment/system-priority-app, kv-e2e-scheduling/Deployment/tolerate-everything

</details>

<details>
<summary>Remediation: resource-requests-missing (9 resources affected)</summary>

## Why This Matters

Resource requests tell the Kubernetes scheduler how much CPU and memory your container needs. Without requests, the scheduler treats the pod as needing zero resources and may pack too many pods onto a single node. This leads to overcommitment, resource contention, throttling, and OOM kills under load.

## How to Fix

Set resource requests based on your application's steady-state usage:

```yaml
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 256Mi
```

Observe your application's actual resource consumption using `kubectl top` or a monitoring tool, then set requests to match the typical steady-state usage.

## Learn More

Resource requests determine the pod's QoS class and scheduling behavior. Pods with requests equal to limits receive Guaranteed QoS. Use Vertical Pod Autoscaler (VPA) to automatically recommend request values.

**Affected resources:** kv-e2e-scheduling/Deployment/control-plane-tolerator, kv-e2e-scheduling/Deployment/hpa-target-no-requests, kv-e2e-scheduling/Deployment/no-pdb-app, kv-e2e-scheduling/Deployment/no-priority-app, kv-e2e-scheduling/Deployment/no-topology-spread-app, kv-e2e-scheduling/Deployment/preemptible-affinity-deploy, kv-e2e-scheduling/Deployment/spot-selector-deploy, kv-e2e-scheduling/Deployment/system-priority-app, kv-e2e-scheduling/Deployment/tolerate-everything

</details>

<details>
<summary>Remediation: run-as-group (9 resources affected)</summary>

## Why This Matters

Without an explicit runAsGroup, the container process defaults to GID 0 (the root group). Files and sockets owned by the root group become accessible to the container, including potentially sensitive host files if volumes are mounted. This widens the attack surface unnecessarily.

## How to Fix

Set an explicit non-root group in the securityContext:

```yaml
securityContext:
  runAsGroup: 1000
  runAsUser: 1000
  runAsNonRoot: true
```

Ensure the container image's application files and directories are readable by the specified GID. You may need to adjust file ownership in your Dockerfile with `chown`.

## Learn More

This aligns with CIS Benchmark 5.2.6 and the Pod Security Standards "Restricted" profile. Always set runAsUser, runAsGroup, and runAsNonRoot together for comprehensive identity control.

**Affected resources:** kv-e2e-scheduling/Deployment/control-plane-tolerator, kv-e2e-scheduling/Deployment/hpa-target-no-requests, kv-e2e-scheduling/Deployment/no-pdb-app, kv-e2e-scheduling/Deployment/no-priority-app, kv-e2e-scheduling/Deployment/no-topology-spread-app, kv-e2e-scheduling/Deployment/preemptible-affinity-deploy, kv-e2e-scheduling/Deployment/spot-selector-deploy, kv-e2e-scheduling/Deployment/system-priority-app, kv-e2e-scheduling/Deployment/tolerate-everything

</details>

<details>
<summary>Remediation: seccomp-profile (9 resources affected)</summary>

## Why This Matters

Without a Seccomp profile, containers can invoke any of the 300+ Linux system calls, leaving the entire kernel attack surface exposed. Kernel vulnerabilities in obscure syscalls are a primary vector for container escapes. Seccomp filtering blocks dangerous syscalls that legitimate applications never use.

## How to Fix

Apply a Seccomp profile at the container or pod level:

```yaml
securityContext:
  seccompProfile:
    type: RuntimeDefault
```

The RuntimeDefault profile blocks approximately 50 dangerous syscalls while allowing normal application behavior. For stricter controls, use a custom Localhost profile tailored to your application's needs. Set the profile at the pod level to apply it to all containers.

## Learn More

Seccomp profiles are required by the Pod Security Standards "Restricted" profile and CIS Benchmark 5.7.2. Use tools like `strace` or the Security Profiles Operator to generate custom profiles for your workloads.

**Affected resources:** kv-e2e-scheduling/Deployment/control-plane-tolerator, kv-e2e-scheduling/Deployment/hpa-target-no-requests, kv-e2e-scheduling/Deployment/no-pdb-app, kv-e2e-scheduling/Deployment/no-priority-app, kv-e2e-scheduling/Deployment/no-topology-spread-app, kv-e2e-scheduling/Deployment/preemptible-affinity-deploy, kv-e2e-scheduling/Deployment/spot-selector-deploy, kv-e2e-scheduling/Deployment/system-priority-app, kv-e2e-scheduling/Deployment/tolerate-everything

</details>

<details>
<summary>Remediation: token-projection-config (9 resources affected)</summary>

## Why This Matters

Without explicit projection configuration, ServiceAccount tokens use Kubernetes defaults: no audience restriction and a long expiration. A stolen token remains valid for an extended period and can be used against any API server endpoint, widening the blast radius of a compromise.

## How to Fix

Add a projected volume with explicit expiration and audience:

```yaml
spec:
  volumes:
    - name: token
      projected:
        sources:
          - serviceAccountToken:
              expirationSeconds: 3600
              audience: my-api
              path: token
  containers:
    - name: app
      volumeMounts:
        - name: token
          mountPath: /var/run/secrets/tokens
          readOnly: true
```

Projected tokens auto-rotate before expiry and are rejected by endpoints outside the specified audience.

## Learn More

See the Kubernetes documentation on projected volumes and service account token volume projection for detailed configuration options.

**Affected resources:** kv-e2e-scheduling/Deployment/control-plane-tolerator, kv-e2e-scheduling/Deployment/hpa-target-no-requests, kv-e2e-scheduling/Deployment/no-pdb-app, kv-e2e-scheduling/Deployment/no-priority-app, kv-e2e-scheduling/Deployment/no-topology-spread-app, kv-e2e-scheduling/Deployment/preemptible-affinity-deploy, kv-e2e-scheduling/Deployment/spot-selector-deploy, kv-e2e-scheduling/Deployment/system-priority-app, kv-e2e-scheduling/Deployment/tolerate-everything

</details>

<details>
<summary>Remediation: hpa-without-requests (1 resources affected)</summary>

## Why This Matters

HPA calculates utilization as a percentage of resource requests (e.g., 80% of requested CPU). Without requests defined on the target Deployment "hpa-target-no-requests", the HPA cannot compute meaningful utilization percentages, leading to erratic scaling behavior, unnecessary scale-ups, or failure to scale entirely.

## How to Fix

Set resource requests on all containers in the target workload:

```yaml
containers:
  - name: app
    resources:
      requests:
        cpu: 250m
        memory: 256Mi
      limits:
        cpu: 500m
        memory: 512Mi
```

Size requests based on observed steady-state usage. The HPA will then scale when actual usage exceeds the target percentage of these requests.

## Learn More

See the Kubernetes HorizontalPodAutoscaler documentation on resource metrics. The HPA algorithm divides current usage by requests to determine the desired replica count.

**Affected resources:** kv-e2e-scheduling/HorizontalPodAutoscaler/hpa-no-requests

</details>

<details>
<summary>Remediation: network-policy-egress-unrestricted (1 resources affected)</summary>

## Why This Matters

Without any egress NetworkPolicy in this namespace, pods can freely send traffic to any destination including the public internet. A compromised pod can exfiltrate sensitive data, reach cloud metadata services (e.g., 169.254.169.254), or establish reverse shells to attacker-controlled servers.

## How to Fix

Create a NetworkPolicy with `Egress` in `policyTypes` to restrict outbound traffic. At minimum, allow DNS resolution:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-egress
  namespace: my-namespace
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector: {}
      ports:
        - port: 53
          protocol: UDP
```

Add additional egress rules for specific services your workloads need to reach.

## Learn More

See the Kubernetes NetworkPolicy documentation and CIS Kubernetes Benchmark 5.3.2. Egress controls are a key defense-in-depth measure recommended by the NSA/CISA Kubernetes Hardening Guide.

**Affected resources:** kv-e2e-scheduling/Namespace/kv-e2e-scheduling

</details>

<details>
<summary>Remediation: psa-labels-missing (1 resources affected)</summary>

## Why This Matters

Without PSA enforcement labels, any pod configuration is allowed in this namespace, including privileged containers, host namespace access, and root execution. This bypasses Kubernetes' built-in Pod Security Standards and leaves the namespace vulnerable to workloads that could compromise the node.

## How to Fix

Add Pod Security Admission labels to enforce a security profile on all pods in the namespace:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: kv-e2e-scheduling
  labels:
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

Start with `baseline` enforcement to block known privilege escalations, then upgrade to `restricted` after verifying all workloads are compliant.

## Learn More

See the Kubernetes Pod Security Admission documentation and CIS Kubernetes Benchmark 5.2. The three-tier approach (enforce, audit, warn) allows gradual adoption of stricter profiles.

**Affected resources:** kv-e2e-scheduling/Namespace/kv-e2e-scheduling

</details>

<details>
<summary>Remediation: node-affinity-untrusted (2 resources affected)</summary>

## Why This Matters

Node affinity rules targeting spot, preemptible, or ephemeral nodes direct sensitive workloads to infrastructure that can be terminated without notice. This puts availability at risk and may violate data residency requirements if workloads are moved unexpectedly.

## How to Fix

Update the nodeAffinity to target trusted, stable node pools:

```yaml
spec:
  affinity:
    nodeAffinity:
      requiredDuringSchedulingIgnoredDuringExecution:
        nodeSelectorTerms:
          - matchExpressions:
              - key: node-pool
                operator: In
                values: [trusted-dedicated]
```

Use preferredDuringScheduling for cost optimization of non-critical workloads on spot nodes.

## Learn More

See the Kubernetes node affinity documentation and your cloud provider's guidance on spot instance best practices. The CIS Benchmark recommends explicit node targeting for security-sensitive workloads.

**Affected resources:** kv-e2e-scheduling/Deployment/preemptible-affinity-deploy, kv-e2e-scheduling/Deployment/spot-selector-deploy

</details>

<details>
<summary>Remediation: toleration-all (1 resources affected)</summary>

## Why This Matters

A catch-all toleration (operator: Exists with an empty key) allows the pod to schedule on any node, including control-plane nodes, GPU nodes, and nodes tainted for isolation. This bypasses scheduling boundaries and can place workloads on nodes where they should not run, creating security and stability risks.

## How to Fix

Replace the catch-all toleration with specific tolerations for the taints your workload actually needs:

```yaml
spec:
  tolerations:
    - key: dedicated
      operator: Equal
      value: monitoring
      effect: NoSchedule
    # Remove this catch-all:
    # - operator: Exists
```

Catch-all tolerations are only appropriate for DaemonSets that must run on every node (e.g., log collectors, node monitors).

## Learn More

Review the Kubernetes taints and tolerations documentation for guidance on scoping tolerations. The CIS Benchmark recommends explicit toleration keys to maintain scheduling boundaries.

**Affected resources:** kv-e2e-scheduling/Deployment/tolerate-everything

</details>

<details>
<summary>Remediation: ephemeral-storage-limits (9 resources affected)</summary>

## Why This Matters

Ephemeral storage includes container logs, emptyDir volumes, and the writable container layer. Without limits, a single container can fill the node's root disk, triggering eviction of all pods on that node and potentially causing a cascading failure across your cluster. This is a common denial-of-service vector.

## How to Fix

Set ephemeral-storage limits alongside your CPU and memory limits:

```yaml
resources:
  limits:
    ephemeral-storage: 1Gi
  requests:
    ephemeral-storage: 500Mi
```

Estimate your application's disk usage from logs, temporary files, and cache data. If your application writes large temporary files, consider using a PersistentVolumeClaim instead of ephemeral storage.

## Learn More

The kubelet evicts pods that exceed their ephemeral-storage limit. Use LimitRange to set default ephemeral-storage limits at the namespace level to catch containers that omit this setting.

**Affected resources:** kv-e2e-scheduling/Deployment/control-plane-tolerator, kv-e2e-scheduling/Deployment/hpa-target-no-requests, kv-e2e-scheduling/Deployment/no-pdb-app, kv-e2e-scheduling/Deployment/no-priority-app, kv-e2e-scheduling/Deployment/no-topology-spread-app, kv-e2e-scheduling/Deployment/preemptible-affinity-deploy, kv-e2e-scheduling/Deployment/spot-selector-deploy, kv-e2e-scheduling/Deployment/system-priority-app, kv-e2e-scheduling/Deployment/tolerate-everything

</details>

<details>
<summary>Remediation: image-no-digest (9 resources affected)</summary>

## Why This Matters

Image tags are mutable pointers -- a registry administrator or attacker can re-push a different image under the same tag. Without a digest, you have no cryptographic guarantee that the image you deploy is the one you tested.

## How to Fix

Pin images by their SHA-256 content digest for a fully immutable reference:

```yaml
containers:
  - name: app
    image: nginx@sha256:a8281ce420348a01ea6e   # Immutable
```

Use `crane digest nginx:1.25.3` or `skopeo inspect` to resolve a tag to its digest during CI/CD, then commit the pinned reference.

## Learn More

SLSA Level 1+ and NIST SP 800-190 recommend digest pinning for container supply chain integrity. See the Kubernetes images documentation for details.

**Affected resources:** kv-e2e-scheduling/Deployment/control-plane-tolerator, kv-e2e-scheduling/Deployment/hpa-target-no-requests, kv-e2e-scheduling/Deployment/no-pdb-app, kv-e2e-scheduling/Deployment/no-priority-app, kv-e2e-scheduling/Deployment/no-topology-spread-app, kv-e2e-scheduling/Deployment/preemptible-affinity-deploy, kv-e2e-scheduling/Deployment/spot-selector-deploy, kv-e2e-scheduling/Deployment/system-priority-app, kv-e2e-scheduling/Deployment/tolerate-everything

</details>

<details>
<summary>Remediation: liveness-readiness-probes (18 resources affected)</summary>

## Why This Matters

Without a liveness probe, Kubernetes cannot detect when a container has become unresponsive or deadlocked. The container continues running and consuming resources while failing to serve traffic. Users experience timeouts and errors until someone manually intervenes.

## How to Fix

Add a liveness probe that checks the container's health:

```yaml
containers:
  - name: app
    livenessProbe:
      httpGet:
        path: /healthz
        port: 8080
      initialDelaySeconds: 15
      periodSeconds: 10
      failureThreshold: 3
```

Use `httpGet` for HTTP services, `tcpSocket` for TCP services, or `exec` with a custom health check script for non-network workloads.

## Learn More

See the Kubernetes documentation on container probes. Set initialDelaySeconds high enough for your application to start, and consider adding a startupProbe for slow-starting containers.

**Affected resources:** kv-e2e-scheduling/Deployment/control-plane-tolerator, kv-e2e-scheduling/Deployment/control-plane-tolerator, kv-e2e-scheduling/Deployment/hpa-target-no-requests, kv-e2e-scheduling/Deployment/hpa-target-no-requests, kv-e2e-scheduling/Deployment/no-pdb-app, kv-e2e-scheduling/Deployment/no-pdb-app, kv-e2e-scheduling/Deployment/no-priority-app, kv-e2e-scheduling/Deployment/no-priority-app, kv-e2e-scheduling/Deployment/no-topology-spread-app, kv-e2e-scheduling/Deployment/no-topology-spread-app, kv-e2e-scheduling/Deployment/preemptible-affinity-deploy, kv-e2e-scheduling/Deployment/preemptible-affinity-deploy, kv-e2e-scheduling/Deployment/spot-selector-deploy, kv-e2e-scheduling/Deployment/spot-selector-deploy, kv-e2e-scheduling/Deployment/system-priority-app, kv-e2e-scheduling/Deployment/system-priority-app, kv-e2e-scheduling/Deployment/tolerate-everything, kv-e2e-scheduling/Deployment/tolerate-everything

</details>

<details>
<summary>Remediation: priority-class-missing (8 resources affected)</summary>

## Why This Matters

Without a PriorityClass, pods receive default priority (typically 0) and are among the first to be evicted during resource pressure or node maintenance. This means important application workloads may be killed before less critical ones, leading to unpredictable outages.

## How to Fix

Define PriorityClasses for your workloads and assign them appropriately:

```yaml
apiVersion: scheduling.k8s.io/v1
kind: PriorityClass
metadata:
  name: app-medium
value: 100000
---
# Reference in your workload:
spec:
  priorityClassName: app-medium
```

Create a tiered priority scheme (e.g., app-critical: 500000, app-medium: 100000, app-low: 10000) that reflects your workload importance hierarchy.

## Learn More

Refer to the Kubernetes Pod Priority and Preemption documentation. Establishing a consistent priority scheme across namespaces ensures predictable eviction behavior during resource contention.

**Affected resources:** kv-e2e-scheduling/Deployment/control-plane-tolerator, kv-e2e-scheduling/Deployment/hpa-target-no-requests, kv-e2e-scheduling/Deployment/no-pdb-app, kv-e2e-scheduling/Deployment/no-priority-app, kv-e2e-scheduling/Deployment/no-topology-spread-app, kv-e2e-scheduling/Deployment/preemptible-affinity-deploy, kv-e2e-scheduling/Deployment/spot-selector-deploy, kv-e2e-scheduling/Deployment/tolerate-everything

</details>

<details>
<summary>Remediation: runtime-class (9 resources affected)</summary>

## Why This Matters

Without a RuntimeClass, pods use the default container runtime (typically runc), which shares the host kernel directly with containers. A kernel vulnerability can allow container escape to the host. Sandboxed runtimes like gVisor or Kata Containers add an additional isolation layer that intercepts system calls or runs containers in lightweight VMs.

## How to Fix

Specify a sandboxed RuntimeClass in the pod spec:

```yaml
spec:
  runtimeClassName: gvisor
```

Available RuntimeClasses depend on your cluster configuration. Common options include `gvisor` (user-space kernel), `kata` (micro-VMs), and `firecracker`. Check your cluster's available RuntimeClasses with `kubectl get runtimeclasses`.

## Learn More

Sandboxed runtimes are especially important for multi-tenant clusters and workloads processing untrusted input. They add latency overhead, so evaluate performance requirements. See the Kubernetes RuntimeClass documentation.

**Affected resources:** kv-e2e-scheduling/Deployment/control-plane-tolerator, kv-e2e-scheduling/Deployment/hpa-target-no-requests, kv-e2e-scheduling/Deployment/no-pdb-app, kv-e2e-scheduling/Deployment/no-priority-app, kv-e2e-scheduling/Deployment/no-topology-spread-app, kv-e2e-scheduling/Deployment/preemptible-affinity-deploy, kv-e2e-scheduling/Deployment/spot-selector-deploy, kv-e2e-scheduling/Deployment/system-priority-app, kv-e2e-scheduling/Deployment/tolerate-everything

</details>

<details>
<summary>Remediation: topology-spread (9 resources affected)</summary>

## Why This Matters

Without topology spread constraints, the scheduler may place all replicas on the same node or in the same availability zone. If that node or zone fails, your entire service goes down despite having multiple replicas. This negates the high-availability benefits of running multiple pods.

## How to Fix

Add topology spread constraints to distribute replicas across failure domains:

```yaml
spec:
  topologySpreadConstraints:
    - maxSkew: 1
      topologyKey: kubernetes.io/hostname
      whenUnsatisfiable: DoNotSchedule
      labelSelector:
        matchLabels:
          app: my-app
    - maxSkew: 1
      topologyKey: topology.kubernetes.io/zone
      whenUnsatisfiable: ScheduleAnyway
```

Use `kubernetes.io/hostname` for node-level spreading and `topology.kubernetes.io/zone` for zone-level spreading.

## Learn More

See the Kubernetes Pod Topology Spread Constraints documentation. Combining hostname and zone constraints provides both node-level and zone-level fault tolerance.

**Affected resources:** kv-e2e-scheduling/Deployment/control-plane-tolerator, kv-e2e-scheduling/Deployment/hpa-target-no-requests, kv-e2e-scheduling/Deployment/no-pdb-app, kv-e2e-scheduling/Deployment/no-priority-app, kv-e2e-scheduling/Deployment/no-topology-spread-app, kv-e2e-scheduling/Deployment/preemptible-affinity-deploy, kv-e2e-scheduling/Deployment/spot-selector-deploy, kv-e2e-scheduling/Deployment/system-priority-app, kv-e2e-scheduling/Deployment/tolerate-everything

</details>

<details>
<summary>Remediation: pod-disruption-budget (3 resources affected)</summary>

## Why This Matters

Without a PodDisruptionBudget, Kubernetes can evict all replicas of your workload simultaneously during voluntary disruptions like node drains, cluster upgrades, or autoscaler scale-downs. This causes complete service downtime even though you have multiple replicas.

## How to Fix

Create a PodDisruptionBudget that matches your workload's pod labels:

```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: my-app-pdb
spec:
  minAvailable: 1              # Or use maxUnavailable: 1
  selector:
    matchLabels:
      app: my-app              # Must match your Deployment/StatefulSet pod labels
```

Use `minAvailable` to guarantee a minimum number of running pods, or `maxUnavailable` to limit how many can be down at once.

## Learn More

See the Kubernetes PodDisruptionBudget documentation for details on voluntary disruption handling. PDBs are essential for production workloads that need high availability during cluster maintenance.

**Affected resources:** kv-e2e-scheduling/Deployment/hpa-target-no-requests, kv-e2e-scheduling/Deployment/no-pdb-app, kv-e2e-scheduling/Deployment/no-topology-spread-app

</details>

<details>
<summary>Remediation: limit-range-missing (1 resources affected)</summary>

## Why This Matters

Without a LimitRange, any container can be created without resource constraints. A single runaway or malicious pod can consume all node CPU and memory, causing denial of service for other workloads on the same node.

## How to Fix

Create a LimitRange in the namespace to set default and maximum resource constraints:

```yaml
apiVersion: v1
kind: LimitRange
metadata:
  name: default-limits
  namespace: my-app
spec:
  limits:
    - type: Container
      default:
        cpu: 500m
        memory: 256Mi
      defaultRequest:
        cpu: 100m
        memory: 128Mi
      max:
        cpu: "2"
        memory: 1Gi
```

Containers that omit resource requests/limits will inherit these defaults automatically.

## Learn More

CIS Kubernetes Benchmark 5.2.1 recommends LimitRanges for resource governance. See https://kubernetes.io/docs/concepts/policy/limit-range/ for configuration details.

**Affected resources:** kv-e2e-scheduling/Namespace/kv-e2e-scheduling

</details>

<details>
<summary>Remediation: resource-quota-missing (1 resources affected)</summary>

## Why This Matters

Without a ResourceQuota, a single namespace can consume the entire cluster's CPU, memory, and storage. This creates a noisy-neighbor problem where one team's workloads starve others, and makes capacity planning impossible.

## How to Fix

Create a ResourceQuota to cap the namespace's total resource consumption:

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: compute-quota
  namespace: my-app
spec:
  hard:
    requests.cpu: "10"
    requests.memory: 20Gi
    limits.cpu: "20"
    limits.memory: 40Gi
    pods: "50"
    services: "10"
```

Tune quota values based on the namespace's actual workload requirements and cluster capacity.

## Learn More

CIS Kubernetes Benchmark 5.2.2 recommends ResourceQuotas for multi-tenant clusters. See https://kubernetes.io/docs/concepts/policy/resource-quotas/ for quota configuration and enforcement behavior.

**Affected resources:** kv-e2e-scheduling/Namespace/kv-e2e-scheduling

</details>

### kv-e2e-secrets (80 findings — 🟠15 🟡44 🔵21)

| Severity | Check | Resources | Message | Frameworks |
|----------|-------|-----------|---------|-----------|
| 🟠 High | secrets-in-configmap | **4 resources** | ConfigMap "app-config-sensitive" has key "db_password" that appears to contain a secret | CIS 5.4.1 · MITRE T1552 · NSA 5.1 |
| 🟠 High | automount-token | **2 resources** | Deployment "app-with-hardcoded-secrets" auto-mounts a ServiceAccount token. Most workloads do not need Kubernetes API access. | CIS 5.1.6 · MITRE T1552.007 · NSA 3.2 |
| 🟠 High | default-service-account | **2 resources** | Deployment "app-with-hardcoded-secrets" uses the default ServiceAccount, which may have unintended permissions. | CIS 5.1.5 · CIS 5.1.6 · MITRE T1078.001 · NSA 3.1 · NSA 3.2 |
| 🟠 High | privilege-escalation | **3 resources** | Container "app" does not set allowPrivilegeEscalation to false, permitting privilege escalation. | CIS 5.2.6 · MITRE T1068 · MITRE T1611 · NSA 1.1 · NSA 2.1 |
| 🟠 High | run-as-root | **3 resources** | Container "app" does not set runAsNonRoot: true and may run as root. | CIS 5.2.7 · MITRE T1611 · NSA 1.1 |
| 🟠 High | network-policy-missing | kv-e2e-secrets/Namespace/kv-e2e-secrets | Namespace "kv-e2e-secrets" has no NetworkPolicy defined. All pods are unrestricted. | CIS 5.3.2 · MITRE T1046 · NSA 4.1 · NSA 4.2 |
| 🟡 Medium | apparmor-profile | **3 resources** | Container "app" does not have an AppArmor profile set. | CIS 5.6.3 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | capabilities-not-dropped | **3 resources** | Container "app" does not drop ALL capabilities, leaving it with unnecessary default privileges. | CIS 5.2.8 · CIS 5.2.10 · MITRE T1068 · NSA 1.1 |
| 🟡 Medium | image-pull-policy | **3 resources** | Container "app" uses a mutable image tag with pullPolicy "IfNotPresent" (image: nginx:1.25), risking stale images. | CIS 5.5.1 · MITRE T1525 · NSA 1.4 |
| 🟡 Medium | psa-restricted-violations | **9 resources** | Deployment "app-with-hardcoded-secrets" container "app" violates PSS Restricted: runAsNonRoot is not true. | CIS 5.2.1 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | read-only-rootfs | **3 resources** | Container "app" does not have a read-only root filesystem. | CIS 5.6.3 · MITRE T1565.001 · NSA 1.2 |
| 🟡 Medium | resource-limits-missing | **3 resources** | Container "app" is missing both CPU and memory limits. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🟡 Medium | resource-requests-missing | **3 resources** | Container "app" is missing both CPU and memory requests. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🟡 Medium | run-as-group | **3 resources** | Container "app" does not set runAsGroup; the process will run as GID 0 (root group) by default. | CIS 5.2.7 · MITRE T1068 · NSA 1.1 |
| 🟡 Medium | seccomp-profile | **3 resources** | Container "app" does not have a Seccomp profile set at either the container or pod level. | CIS 5.6.2 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | secrets-in-env | **7 resources** | container "app" passes secret "hardcoded-api-credentials" key "api-token" via environment variable | CIS 5.4.1 · CIS 5.4.2 · MITRE T1552 · NSA 5.1 |
| 🟡 Medium | token-projection-config | kv-e2e-secrets/Deployment/app-with-hardcoded-secrets | Deployment "app-with-hardcoded-secrets" does not use explicitly configured projected ServiceAccount tokens with expiry and audience restrictions. | CIS 5.1.6 · MITRE T1552.007 · NSA 3.2 |
| 🟡 Medium | projected-volume-security | kv-e2e-secrets/Pod/app-with-secret-env | Pod "app-with-secret-env" has projected volume "kube-api-access-7xkpl" with defaultMode 0644 which is too permissive. | CIS 5.4.1 · MITRE T1552 · NSA 5.1 |
| 🟡 Medium | network-policy-egress-unrestricted | kv-e2e-secrets/Namespace/kv-e2e-secrets | Namespace "kv-e2e-secrets" has no NetworkPolicy with egress restrictions. Pods can reach any external destination. | CIS 5.3.2 · MITRE T1048 · NSA 4.2 |
| 🟡 Medium | psa-labels-missing | kv-e2e-secrets/Namespace/kv-e2e-secrets | Namespace "kv-e2e-secrets" is missing the pod-security.kubernetes.io/enforce label; pod security is not enforced. | CIS 5.2.1 · MITRE T1610 · NSA 2.1 |
| 🔵 Low | ephemeral-storage-limits | **3 resources** | Container "app" is missing ephemeral-storage limits. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | image-no-digest | **3 resources** | Container "app" image is not pinned by digest (image: nginx:1.25), allowing tag mutation. | CIS 5.5.1 · MITRE T1525 · NSA 1.4 |
| 🔵 Low | liveness-readiness-probes | **4 resources** | Container "app" has no liveness probe configured. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | priority-class-missing | **2 resources** | Deployment "app-with-hardcoded-secrets" has no PriorityClass set; it will be evicted first during resource pressure. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | runtime-class | **2 resources** | Pod "app-with-hardcoded-secrets" does not specify a RuntimeClass, using the default (unsandboxed) runtime. | CIS 5.6.3 · MITRE T1611 · NSA 2.1 |
| 🔵 Low | topology-spread | **2 resources** | Deployment "app-with-hardcoded-secrets" has no topology spread constraints; all replicas may be scheduled on the same node. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | secrets-default-type | **3 resources** | Secret "db-auth-opaque" uses Opaque type but data keys suggest it should be "kubernetes.io/basic-auth". | CIS 5.4.1 · MITRE T1552 · NSA 5.1 |
| 🔵 Low | limit-range-missing | kv-e2e-secrets/Namespace/kv-e2e-secrets | Namespace "kv-e2e-secrets" has no LimitRange defined. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | resource-quota-missing | kv-e2e-secrets/Namespace/kv-e2e-secrets | Namespace "kv-e2e-secrets" has no ResourceQuota defined. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |

<details>
<summary>secrets-in-configmap: 4 affected resources</summary>

- `kv-e2e-secrets/ConfigMap/app-config-sensitive`
- `kv-e2e-secrets/ConfigMap/app-config-sensitive`
- `kv-e2e-secrets/ConfigMap/app-config-sensitive`
- `kv-e2e-secrets/ConfigMap/app-config-sensitive`

</details>

<details>
<summary>automount-token: 2 affected resources</summary>

- `kv-e2e-secrets/Deployment/app-with-hardcoded-secrets`
- `kv-e2e-secrets/Pod/app-with-secret-env`

</details>

<details>
<summary>default-service-account: 2 affected resources</summary>

- `kv-e2e-secrets/Deployment/app-with-hardcoded-secrets`
- `kv-e2e-secrets/Pod/app-with-secret-env`

</details>

<details>
<summary>privilege-escalation: 3 affected resources</summary>

- `kv-e2e-secrets/Deployment/app-with-hardcoded-secrets (app)`
- `kv-e2e-secrets/Pod/app-with-secret-env (app)`
- `kv-e2e-secrets/Pod/app-with-secret-env (db-init)`

</details>

<details>
<summary>run-as-root: 3 affected resources</summary>

- `kv-e2e-secrets/Deployment/app-with-hardcoded-secrets (app)`
- `kv-e2e-secrets/Pod/app-with-secret-env (app)`
- `kv-e2e-secrets/Pod/app-with-secret-env (db-init)`

</details>

<details>
<summary>apparmor-profile: 3 affected resources</summary>

- `kv-e2e-secrets/Deployment/app-with-hardcoded-secrets (app)`
- `kv-e2e-secrets/Pod/app-with-secret-env (app)`
- `kv-e2e-secrets/Pod/app-with-secret-env (db-init)`

</details>

<details>
<summary>capabilities-not-dropped: 3 affected resources</summary>

- `kv-e2e-secrets/Deployment/app-with-hardcoded-secrets (app)`
- `kv-e2e-secrets/Pod/app-with-secret-env (app)`
- `kv-e2e-secrets/Pod/app-with-secret-env (db-init)`

</details>

<details>
<summary>image-pull-policy: 3 affected resources</summary>

- `kv-e2e-secrets/Deployment/app-with-hardcoded-secrets (app)`
- `kv-e2e-secrets/Pod/app-with-secret-env (app)`
- `kv-e2e-secrets/Pod/app-with-secret-env (db-init)`

</details>

<details>
<summary>psa-restricted-violations: 9 affected resources</summary>

- `kv-e2e-secrets/Deployment/app-with-hardcoded-secrets (app)`
- `kv-e2e-secrets/Deployment/app-with-hardcoded-secrets (app)`
- `kv-e2e-secrets/Deployment/app-with-hardcoded-secrets (app)`
- `kv-e2e-secrets/Pod/app-with-secret-env (app)`
- `kv-e2e-secrets/Pod/app-with-secret-env (app)`
- `kv-e2e-secrets/Pod/app-with-secret-env (app)`
- `kv-e2e-secrets/Pod/app-with-secret-env (db-init)`
- `kv-e2e-secrets/Pod/app-with-secret-env (db-init)`
- `kv-e2e-secrets/Pod/app-with-secret-env (db-init)`

</details>

<details>
<summary>read-only-rootfs: 3 affected resources</summary>

- `kv-e2e-secrets/Deployment/app-with-hardcoded-secrets (app)`
- `kv-e2e-secrets/Pod/app-with-secret-env (app)`
- `kv-e2e-secrets/Pod/app-with-secret-env (db-init)`

</details>

<details>
<summary>resource-limits-missing: 3 affected resources</summary>

- `kv-e2e-secrets/Deployment/app-with-hardcoded-secrets (app)`
- `kv-e2e-secrets/Pod/app-with-secret-env (app)`
- `kv-e2e-secrets/Pod/app-with-secret-env (db-init)`

</details>

<details>
<summary>resource-requests-missing: 3 affected resources</summary>

- `kv-e2e-secrets/Deployment/app-with-hardcoded-secrets (app)`
- `kv-e2e-secrets/Pod/app-with-secret-env (app)`
- `kv-e2e-secrets/Pod/app-with-secret-env (db-init)`

</details>

<details>
<summary>run-as-group: 3 affected resources</summary>

- `kv-e2e-secrets/Deployment/app-with-hardcoded-secrets (app)`
- `kv-e2e-secrets/Pod/app-with-secret-env (app)`
- `kv-e2e-secrets/Pod/app-with-secret-env (db-init)`

</details>

<details>
<summary>seccomp-profile: 3 affected resources</summary>

- `kv-e2e-secrets/Deployment/app-with-hardcoded-secrets (app)`
- `kv-e2e-secrets/Pod/app-with-secret-env (app)`
- `kv-e2e-secrets/Pod/app-with-secret-env (db-init)`

</details>

<details>
<summary>secrets-in-env: 7 affected resources</summary>

- `kv-e2e-secrets/Deployment/app-with-hardcoded-secrets (app)`
- `kv-e2e-secrets/Deployment/app-with-hardcoded-secrets (app)`
- `kv-e2e-secrets/Deployment/app-with-hardcoded-secrets (app)`
- `kv-e2e-secrets/Pod/app-with-secret-env (app)`
- `kv-e2e-secrets/Pod/app-with-secret-env (app)`
- `kv-e2e-secrets/Pod/app-with-secret-env (app)`
- `kv-e2e-secrets/Pod/app-with-secret-env (db-init)`

</details>

<details>
<summary>ephemeral-storage-limits: 3 affected resources</summary>

- `kv-e2e-secrets/Deployment/app-with-hardcoded-secrets (app)`
- `kv-e2e-secrets/Pod/app-with-secret-env (app)`
- `kv-e2e-secrets/Pod/app-with-secret-env (db-init)`

</details>

<details>
<summary>image-no-digest: 3 affected resources</summary>

- `kv-e2e-secrets/Deployment/app-with-hardcoded-secrets (app)`
- `kv-e2e-secrets/Pod/app-with-secret-env (app)`
- `kv-e2e-secrets/Pod/app-with-secret-env (db-init)`

</details>

<details>
<summary>liveness-readiness-probes: 4 affected resources</summary>

- `kv-e2e-secrets/Deployment/app-with-hardcoded-secrets (app)`
- `kv-e2e-secrets/Deployment/app-with-hardcoded-secrets (app)`
- `kv-e2e-secrets/Pod/app-with-secret-env (app)`
- `kv-e2e-secrets/Pod/app-with-secret-env (app)`

</details>

<details>
<summary>priority-class-missing: 2 affected resources</summary>

- `kv-e2e-secrets/Deployment/app-with-hardcoded-secrets`
- `kv-e2e-secrets/Pod/app-with-secret-env`

</details>

<details>
<summary>runtime-class: 2 affected resources</summary>

- `kv-e2e-secrets/Deployment/app-with-hardcoded-secrets`
- `kv-e2e-secrets/Pod/app-with-secret-env`

</details>

<details>
<summary>topology-spread: 2 affected resources</summary>

- `kv-e2e-secrets/Deployment/app-with-hardcoded-secrets`
- `kv-e2e-secrets/Pod/app-with-secret-env`

</details>

<details>
<summary>secrets-default-type: 3 affected resources</summary>

- `kv-e2e-secrets/Secret/db-auth-opaque`
- `kv-e2e-secrets/Secret/db-credentials`
- `kv-e2e-secrets/Secret/tls-cert-opaque`

</details>

<details>
<summary>Remediation: secrets-in-configmap (4 resources affected)</summary>

## Why This Matters

ConfigMaps are not encrypted at rest and have weaker RBAC defaults than Secrets. Any user with namespace read access can view ConfigMap data, making them an inappropriate store for passwords, tokens, API keys, or private keys.

## How to Fix

Move sensitive values from the ConfigMap into a Secret resource:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-secret
type: Opaque
stringData:
  password: "<managed-externally>"
```

For production workloads, use an external secret manager (Vault, AWS Secrets Manager, GCP Secret Manager) with the External Secrets Operator.

## Learn More

CIS Kubernetes Benchmark 5.4.1 requires secrets to be stored in Secret objects, not ConfigMaps. See the Kubernetes Secrets documentation for proper usage.

**Affected resources:** kv-e2e-secrets/ConfigMap/app-config-sensitive, kv-e2e-secrets/ConfigMap/app-config-sensitive, kv-e2e-secrets/ConfigMap/app-config-sensitive, kv-e2e-secrets/ConfigMap/app-config-sensitive

</details>

<details>
<summary>Remediation: automount-token (2 resources affected)</summary>

## Why This Matters

When a ServiceAccount token is auto-mounted, every container in the pod can call the Kubernetes API. If a container is compromised through a vulnerability or misconfiguration, the attacker gains API access to enumerate resources, read secrets, or escalate privileges.

## How to Fix

Disable auto-mounting at the pod spec level for workloads that do not need API access:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      automountServiceAccountToken: false
      containers:
        - name: app
          image: my-app:latest
```

For workloads that do require API access, use projected tokens with bounded lifetime and audience restrictions instead of the default long-lived token.

## Learn More

Refer to the Kubernetes documentation on configuring service accounts for pods and CIS Kubernetes Benchmark 5.1.6 for auto-mount token guidance.

**Affected resources:** kv-e2e-secrets/Deployment/app-with-hardcoded-secrets, kv-e2e-secrets/Pod/app-with-secret-env

</details>

<details>
<summary>Remediation: default-service-account (2 resources affected)</summary>

## Why This Matters

The default ServiceAccount is shared by every pod in a namespace. If any pod is compromised, the attacker inherits whatever permissions have been granted to the default account via role bindings, enabling lateral movement across all workloads sharing it.

## How to Fix

Create a dedicated ServiceAccount for each workload and reference it in the pod spec:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-app
  namespace: production
automountServiceAccountToken: false
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      serviceAccountName: my-app
```

Grant only the permissions the workload actually needs via a dedicated Role and RoleBinding.

## Learn More

See the Kubernetes documentation on managing service accounts and CIS Kubernetes Benchmark 5.1.5 for guidance on ensuring default service accounts are not actively used.

**Affected resources:** kv-e2e-secrets/Deployment/app-with-hardcoded-secrets, kv-e2e-secrets/Pod/app-with-secret-env

</details>

<details>
<summary>Remediation: privilege-escalation (3 resources affected)</summary>

## Why This Matters

By default, Kubernetes allows containers to escalate privileges via setuid/setgid binaries, which let a process gain more permissions than its parent. An attacker can exploit this using setuid binaries already present in the container image (like `su`, `sudo`, or `ping`) to elevate from a low-privilege user to root.

## How to Fix

Explicitly disable privilege escalation in the container's securityContext:

```yaml
securityContext:
  allowPrivilegeEscalation: false
  runAsNonRoot: true
  capabilities:
    drop: ["ALL"]
```

This blocks the use of setuid/setgid binaries and prevents the no_new_privs Linux flag from being cleared. The vast majority of application containers do not need privilege escalation.

## Learn More

This is required by the Pod Security Standards "Restricted" profile and CIS Benchmark 5.2.5. Disabling privilege escalation is one of the most impactful single-line security improvements you can make.

**Affected resources:** kv-e2e-secrets/Deployment/app-with-hardcoded-secrets, kv-e2e-secrets/Pod/app-with-secret-env, kv-e2e-secrets/Pod/app-with-secret-env

</details>

<details>
<summary>Remediation: run-as-root (3 resources affected)</summary>

## Why This Matters

Without `runAsNonRoot: true`, Kubernetes does not enforce non-root execution and the container may default to running as UID 0 depending on the image's USER directive. If the image defaults to root, the container process gains full privileges, increasing the blast radius of any compromise or container escape.

## How to Fix

Enforce non-root execution in the securityContext:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
```

With `runAsNonRoot: true`, Kubernetes will reject the pod at admission time if the container image attempts to run as root. Setting an explicit `runAsUser` provides an additional guarantee.

## Learn More

This aligns with CIS Benchmark 5.2.6 and the Pod Security Standards "Restricted" profile. The `runAsNonRoot` field acts as a safety net even when images change their default USER.

**Affected resources:** kv-e2e-secrets/Deployment/app-with-hardcoded-secrets, kv-e2e-secrets/Pod/app-with-secret-env, kv-e2e-secrets/Pod/app-with-secret-env

</details>

<details>
<summary>Remediation: network-policy-missing (1 resources affected)</summary>

## Why This Matters

Without NetworkPolicies, every pod in this namespace can communicate freely with every other pod in the cluster. If an attacker compromises a single pod, they can move laterally to databases, internal APIs, and other sensitive services with no network-level barriers.

## How to Fix

Create a default-deny NetworkPolicy for the namespace, then add targeted allow rules for legitimate traffic:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: my-namespace
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
```

After applying the default-deny, create additional NetworkPolicy resources that whitelist only the specific ingress and egress flows your workloads require.

## Learn More

See the Kubernetes documentation on NetworkPolicies and CIS Kubernetes Benchmark 5.3.2. A CNI plugin that supports NetworkPolicy (Calico, Cilium, Weave Net) must be installed for policies to take effect.

**Affected resources:** kv-e2e-secrets/Namespace/kv-e2e-secrets

</details>

<details>
<summary>Remediation: apparmor-profile (3 resources affected)</summary>

## Why This Matters

AppArmor provides mandatory access control (MAC) that restricts which files, network resources, and capabilities a container process can access. Without an AppArmor profile, the container operates without these restrictions, allowing an attacker with code execution to access any file the container user can read and make unrestricted network connections.

## How to Fix

Apply an AppArmor profile in the container's securityContext (Kubernetes 1.30+):

```yaml
securityContext:
  appArmorProfile:
    type: RuntimeDefault
```

The RuntimeDefault profile provides sensible restrictions for most applications. For tighter control, create a custom Localhost profile that only allows the specific file and network access your application needs.

## Learn More

AppArmor is available on Debian/Ubuntu-based nodes. RHEL/CentOS nodes use SELinux instead. Both provide MAC enforcement. Refer to CIS Benchmark 5.7.5 and the Kubernetes AppArmor documentation.

**Affected resources:** kv-e2e-secrets/Deployment/app-with-hardcoded-secrets, kv-e2e-secrets/Pod/app-with-secret-env, kv-e2e-secrets/Pod/app-with-secret-env

</details>

<details>
<summary>Remediation: capabilities-not-dropped (3 resources affected)</summary>

## Why This Matters

By default, containers receive a set of Linux capabilities including KILL, SETUID, SETGID, and NET_RAW. These defaults are rarely needed by application code and significantly increase the potential damage from a container compromise. Dropping all capabilities follows the principle of least privilege.

## How to Fix

Explicitly drop all capabilities and selectively add back only what your application needs:

```yaml
securityContext:
  capabilities:
    drop: ["ALL"]
    add: ["NET_BIND_SERVICE"]  # Only if needed
```

Most web applications, API servers, and background workers run perfectly with all capabilities dropped. Test your application after making this change to confirm no functionality is lost.

## Learn More

This is required by the Pod Security Standards "Restricted" profile and aligns with CIS Benchmark 5.2.7. Kubernetes best practice is to treat capability grants as exceptions that require explicit justification.

**Affected resources:** kv-e2e-secrets/Deployment/app-with-hardcoded-secrets, kv-e2e-secrets/Pod/app-with-secret-env, kv-e2e-secrets/Pod/app-with-secret-env

</details>

<details>
<summary>Remediation: image-pull-policy (3 resources affected)</summary>

## Why This Matters

When a mutable image tag is used without `imagePullPolicy: Always`, Kubernetes may serve a cached version of the image from the node. If the tag has been updated in the registry (with a security patch or -- worse -- a compromised layer), the running container will not reflect those changes.

## How to Fix

Set `imagePullPolicy: Always` for any container using a mutable tag:

```yaml
containers:
  - name: app
    image: nginx:1.25.3
    imagePullPolicy: Always   # Forces fresh pull each time
```

Alternatively, pin images by digest (`image@sha256:...`), which makes the pull policy irrelevant because the content is immutable.

## Learn More

See the Kubernetes documentation on image pull policies and CIS Kubernetes Benchmark 5.4.2 for pull policy guidance.

**Affected resources:** kv-e2e-secrets/Deployment/app-with-hardcoded-secrets, kv-e2e-secrets/Pod/app-with-secret-env, kv-e2e-secrets/Pod/app-with-secret-env

</details>

<details>
<summary>Remediation: psa-restricted-violations (9 resources affected)</summary>

## Why This Matters

Running as root inside a container means that any container escape vulnerability immediately grants root access on the host node. Even without an escape, root inside the container can modify sensitive files, install packages, and access capabilities that non-root users cannot.

## How to Fix

Set `runAsNonRoot: true` and specify a non-root user ID in the security context:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
```

Set this at the pod level to apply to all containers. Ensure your container image supports running as a non-root user (many official images do).

## Learn More

See the Pod Security Standards Restricted profile and CIS Kubernetes Benchmark 5.2.6. Running as non-root is a fundamental container security best practice.

**Affected resources:** kv-e2e-secrets/Deployment/app-with-hardcoded-secrets, kv-e2e-secrets/Deployment/app-with-hardcoded-secrets, kv-e2e-secrets/Deployment/app-with-hardcoded-secrets, kv-e2e-secrets/Pod/app-with-secret-env, kv-e2e-secrets/Pod/app-with-secret-env, kv-e2e-secrets/Pod/app-with-secret-env, kv-e2e-secrets/Pod/app-with-secret-env, kv-e2e-secrets/Pod/app-with-secret-env, kv-e2e-secrets/Pod/app-with-secret-env

</details>

<details>
<summary>Remediation: read-only-rootfs (3 resources affected)</summary>

## Why This Matters

A writable root filesystem allows an attacker who gains code execution in your container to modify application binaries, install attack tools, plant backdoors, or persist malware across container restarts. Making the filesystem read-only eliminates an entire class of post-exploitation techniques.

## How to Fix

Enable a read-only root filesystem and mount writable volumes only where needed:

```yaml
securityContext:
  readOnlyRootFilesystem: true
volumeMounts:
  - name: tmp
    mountPath: /tmp
volumes:
  - name: tmp
    emptyDir: {}
```

Common paths that need write access include /tmp, /var/cache, and /var/run. Mount each as an emptyDir or tmpfs volume rather than making the entire filesystem writable.

## Learn More

This aligns with CIS Benchmark 5.2.4 and the defense-in-depth principle. Combined with dropping capabilities and running as non-root, a read-only filesystem forms a strong container hardening baseline.

**Affected resources:** kv-e2e-secrets/Deployment/app-with-hardcoded-secrets, kv-e2e-secrets/Pod/app-with-secret-env, kv-e2e-secrets/Pod/app-with-secret-env

</details>

<details>
<summary>Remediation: resource-limits-missing (3 resources affected)</summary>

## Why This Matters

Without resource limits, a single container can consume all available CPU and memory on a node, starving other workloads and triggering cascading failures. An attacker who compromises an unlimited container can mount a denial-of-service attack against the entire node with a simple fork bomb or memory allocation loop.

## How to Fix

Set both CPU and memory limits based on your application's actual resource usage:

```yaml
resources:
  limits:
    cpu: 500m
    memory: 256Mi
  requests:
    cpu: 100m
    memory: 128Mi
```

Profile your application under load to determine appropriate values. Set limits to handle peak usage and requests to match steady-state consumption.

## Learn More

Use LimitRange objects to enforce default limits at the namespace level. Resource limits also determine the pod's QoS class: pods with equal requests and limits get Guaranteed QoS and are last to be evicted.

**Affected resources:** kv-e2e-secrets/Deployment/app-with-hardcoded-secrets, kv-e2e-secrets/Pod/app-with-secret-env, kv-e2e-secrets/Pod/app-with-secret-env

</details>

<details>
<summary>Remediation: resource-requests-missing (3 resources affected)</summary>

## Why This Matters

Resource requests tell the Kubernetes scheduler how much CPU and memory your container needs. Without requests, the scheduler treats the pod as needing zero resources and may pack too many pods onto a single node. This leads to overcommitment, resource contention, throttling, and OOM kills under load.

## How to Fix

Set resource requests based on your application's steady-state usage:

```yaml
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 256Mi
```

Observe your application's actual resource consumption using `kubectl top` or a monitoring tool, then set requests to match the typical steady-state usage.

## Learn More

Resource requests determine the pod's QoS class and scheduling behavior. Pods with requests equal to limits receive Guaranteed QoS. Use Vertical Pod Autoscaler (VPA) to automatically recommend request values.

**Affected resources:** kv-e2e-secrets/Deployment/app-with-hardcoded-secrets, kv-e2e-secrets/Pod/app-with-secret-env, kv-e2e-secrets/Pod/app-with-secret-env

</details>

<details>
<summary>Remediation: run-as-group (3 resources affected)</summary>

## Why This Matters

Without an explicit runAsGroup, the container process defaults to GID 0 (the root group). Files and sockets owned by the root group become accessible to the container, including potentially sensitive host files if volumes are mounted. This widens the attack surface unnecessarily.

## How to Fix

Set an explicit non-root group in the securityContext:

```yaml
securityContext:
  runAsGroup: 1000
  runAsUser: 1000
  runAsNonRoot: true
```

Ensure the container image's application files and directories are readable by the specified GID. You may need to adjust file ownership in your Dockerfile with `chown`.

## Learn More

This aligns with CIS Benchmark 5.2.6 and the Pod Security Standards "Restricted" profile. Always set runAsUser, runAsGroup, and runAsNonRoot together for comprehensive identity control.

**Affected resources:** kv-e2e-secrets/Deployment/app-with-hardcoded-secrets, kv-e2e-secrets/Pod/app-with-secret-env, kv-e2e-secrets/Pod/app-with-secret-env

</details>

<details>
<summary>Remediation: seccomp-profile (3 resources affected)</summary>

## Why This Matters

Without a Seccomp profile, containers can invoke any of the 300+ Linux system calls, leaving the entire kernel attack surface exposed. Kernel vulnerabilities in obscure syscalls are a primary vector for container escapes. Seccomp filtering blocks dangerous syscalls that legitimate applications never use.

## How to Fix

Apply a Seccomp profile at the container or pod level:

```yaml
securityContext:
  seccompProfile:
    type: RuntimeDefault
```

The RuntimeDefault profile blocks approximately 50 dangerous syscalls while allowing normal application behavior. For stricter controls, use a custom Localhost profile tailored to your application's needs. Set the profile at the pod level to apply it to all containers.

## Learn More

Seccomp profiles are required by the Pod Security Standards "Restricted" profile and CIS Benchmark 5.7.2. Use tools like `strace` or the Security Profiles Operator to generate custom profiles for your workloads.

**Affected resources:** kv-e2e-secrets/Deployment/app-with-hardcoded-secrets, kv-e2e-secrets/Pod/app-with-secret-env, kv-e2e-secrets/Pod/app-with-secret-env

</details>

<details>
<summary>Remediation: secrets-in-env (7 resources affected)</summary>

## Why This Matters

Environment variables are visible in pod specs, process listings (`/proc/*/environ`), crash dumps, and log output. They are also inherited by child processes. If a secret leaks through any of these channels, an attacker gains immediate access to the credential.

## How to Fix

Mount secrets as files using a volume instead of environment variables:

```yaml
volumeMounts:
  - name: secret-vol
    mountPath: /etc/secrets
    readOnly: true
volumes:
  - name: secret-vol
    secret:
      secretName: my-secret
```

File-mounted secrets are stored on tmpfs, are not exposed in logs or process listings, and support automatic rotation via the kubelet.

## Learn More

CIS Kubernetes Benchmark 5.4.1 and NSA/CISA Kubernetes Hardening Guide recommend avoiding secrets in environment variables. See the Kubernetes Secrets documentation for volume mount examples.

**Affected resources:** kv-e2e-secrets/Deployment/app-with-hardcoded-secrets, kv-e2e-secrets/Deployment/app-with-hardcoded-secrets, kv-e2e-secrets/Deployment/app-with-hardcoded-secrets, kv-e2e-secrets/Pod/app-with-secret-env, kv-e2e-secrets/Pod/app-with-secret-env, kv-e2e-secrets/Pod/app-with-secret-env, kv-e2e-secrets/Pod/app-with-secret-env

</details>

<details>
<summary>Remediation: token-projection-config (1 resources affected)</summary>

## Why This Matters

Without explicit projection configuration, ServiceAccount tokens use Kubernetes defaults: no audience restriction and a long expiration. A stolen token remains valid for an extended period and can be used against any API server endpoint, widening the blast radius of a compromise.

## How to Fix

Add a projected volume with explicit expiration and audience:

```yaml
spec:
  volumes:
    - name: token
      projected:
        sources:
          - serviceAccountToken:
              expirationSeconds: 3600
              audience: my-api
              path: token
  containers:
    - name: app
      volumeMounts:
        - name: token
          mountPath: /var/run/secrets/tokens
          readOnly: true
```

Projected tokens auto-rotate before expiry and are rejected by endpoints outside the specified audience.

## Learn More

See the Kubernetes documentation on projected volumes and service account token volume projection for detailed configuration options.

**Affected resources:** kv-e2e-secrets/Deployment/app-with-hardcoded-secrets

</details>

<details>
<summary>Remediation: projected-volume-security (1 resources affected)</summary>

## Why This Matters

Projected volumes with overly permissive file modes allow any process in the pod to read sensitive data such as service account tokens and secrets. If a container is compromised, the attacker can easily harvest these credentials to escalate privileges or move laterally within the cluster.

## How to Fix

Reduce the defaultMode to restrict file access:

```yaml
spec:
  volumes:
    - name: kube-api-access-7xkpl
      projected:
        defaultMode: 0400         # Owner read-only (was too permissive)
        sources:
          - serviceAccountToken:
              path: token
```

Use 0400 for read-only access or 0600 if the application must write to the mounted files.

## Learn More

See the Kubernetes Projected Volumes documentation for defaultMode details. The CIS Benchmark recommends file modes of 0600 or lower for sensitive volume mounts to limit exposure within the pod.

**Affected resources:** kv-e2e-secrets/Pod/app-with-secret-env

</details>

<details>
<summary>Remediation: network-policy-egress-unrestricted (1 resources affected)</summary>

## Why This Matters

Without any egress NetworkPolicy in this namespace, pods can freely send traffic to any destination including the public internet. A compromised pod can exfiltrate sensitive data, reach cloud metadata services (e.g., 169.254.169.254), or establish reverse shells to attacker-controlled servers.

## How to Fix

Create a NetworkPolicy with `Egress` in `policyTypes` to restrict outbound traffic. At minimum, allow DNS resolution:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-egress
  namespace: my-namespace
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector: {}
      ports:
        - port: 53
          protocol: UDP
```

Add additional egress rules for specific services your workloads need to reach.

## Learn More

See the Kubernetes NetworkPolicy documentation and CIS Kubernetes Benchmark 5.3.2. Egress controls are a key defense-in-depth measure recommended by the NSA/CISA Kubernetes Hardening Guide.

**Affected resources:** kv-e2e-secrets/Namespace/kv-e2e-secrets

</details>

<details>
<summary>Remediation: psa-labels-missing (1 resources affected)</summary>

## Why This Matters

Without PSA enforcement labels, any pod configuration is allowed in this namespace, including privileged containers, host namespace access, and root execution. This bypasses Kubernetes' built-in Pod Security Standards and leaves the namespace vulnerable to workloads that could compromise the node.

## How to Fix

Add Pod Security Admission labels to enforce a security profile on all pods in the namespace:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: kv-e2e-secrets
  labels:
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

Start with `baseline` enforcement to block known privilege escalations, then upgrade to `restricted` after verifying all workloads are compliant.

## Learn More

See the Kubernetes Pod Security Admission documentation and CIS Kubernetes Benchmark 5.2. The three-tier approach (enforce, audit, warn) allows gradual adoption of stricter profiles.

**Affected resources:** kv-e2e-secrets/Namespace/kv-e2e-secrets

</details>

<details>
<summary>Remediation: ephemeral-storage-limits (3 resources affected)</summary>

## Why This Matters

Ephemeral storage includes container logs, emptyDir volumes, and the writable container layer. Without limits, a single container can fill the node's root disk, triggering eviction of all pods on that node and potentially causing a cascading failure across your cluster. This is a common denial-of-service vector.

## How to Fix

Set ephemeral-storage limits alongside your CPU and memory limits:

```yaml
resources:
  limits:
    ephemeral-storage: 1Gi
  requests:
    ephemeral-storage: 500Mi
```

Estimate your application's disk usage from logs, temporary files, and cache data. If your application writes large temporary files, consider using a PersistentVolumeClaim instead of ephemeral storage.

## Learn More

The kubelet evicts pods that exceed their ephemeral-storage limit. Use LimitRange to set default ephemeral-storage limits at the namespace level to catch containers that omit this setting.

**Affected resources:** kv-e2e-secrets/Deployment/app-with-hardcoded-secrets, kv-e2e-secrets/Pod/app-with-secret-env, kv-e2e-secrets/Pod/app-with-secret-env

</details>

<details>
<summary>Remediation: image-no-digest (3 resources affected)</summary>

## Why This Matters

Image tags are mutable pointers -- a registry administrator or attacker can re-push a different image under the same tag. Without a digest, you have no cryptographic guarantee that the image you deploy is the one you tested.

## How to Fix

Pin images by their SHA-256 content digest for a fully immutable reference:

```yaml
containers:
  - name: app
    image: nginx@sha256:a8281ce420348a01ea6e   # Immutable
```

Use `crane digest nginx:1.25.3` or `skopeo inspect` to resolve a tag to its digest during CI/CD, then commit the pinned reference.

## Learn More

SLSA Level 1+ and NIST SP 800-190 recommend digest pinning for container supply chain integrity. See the Kubernetes images documentation for details.

**Affected resources:** kv-e2e-secrets/Deployment/app-with-hardcoded-secrets, kv-e2e-secrets/Pod/app-with-secret-env, kv-e2e-secrets/Pod/app-with-secret-env

</details>

<details>
<summary>Remediation: liveness-readiness-probes (4 resources affected)</summary>

## Why This Matters

Without a liveness probe, Kubernetes cannot detect when a container has become unresponsive or deadlocked. The container continues running and consuming resources while failing to serve traffic. Users experience timeouts and errors until someone manually intervenes.

## How to Fix

Add a liveness probe that checks the container's health:

```yaml
containers:
  - name: app
    livenessProbe:
      httpGet:
        path: /healthz
        port: 8080
      initialDelaySeconds: 15
      periodSeconds: 10
      failureThreshold: 3
```

Use `httpGet` for HTTP services, `tcpSocket` for TCP services, or `exec` with a custom health check script for non-network workloads.

## Learn More

See the Kubernetes documentation on container probes. Set initialDelaySeconds high enough for your application to start, and consider adding a startupProbe for slow-starting containers.

**Affected resources:** kv-e2e-secrets/Deployment/app-with-hardcoded-secrets, kv-e2e-secrets/Deployment/app-with-hardcoded-secrets, kv-e2e-secrets/Pod/app-with-secret-env, kv-e2e-secrets/Pod/app-with-secret-env

</details>

<details>
<summary>Remediation: priority-class-missing (2 resources affected)</summary>

## Why This Matters

Without a PriorityClass, pods receive default priority (typically 0) and are among the first to be evicted during resource pressure or node maintenance. This means important application workloads may be killed before less critical ones, leading to unpredictable outages.

## How to Fix

Define PriorityClasses for your workloads and assign them appropriately:

```yaml
apiVersion: scheduling.k8s.io/v1
kind: PriorityClass
metadata:
  name: app-medium
value: 100000
---
# Reference in your workload:
spec:
  priorityClassName: app-medium
```

Create a tiered priority scheme (e.g., app-critical: 500000, app-medium: 100000, app-low: 10000) that reflects your workload importance hierarchy.

## Learn More

Refer to the Kubernetes Pod Priority and Preemption documentation. Establishing a consistent priority scheme across namespaces ensures predictable eviction behavior during resource contention.

**Affected resources:** kv-e2e-secrets/Deployment/app-with-hardcoded-secrets, kv-e2e-secrets/Pod/app-with-secret-env

</details>

<details>
<summary>Remediation: runtime-class (2 resources affected)</summary>

## Why This Matters

Without a RuntimeClass, pods use the default container runtime (typically runc), which shares the host kernel directly with containers. A kernel vulnerability can allow container escape to the host. Sandboxed runtimes like gVisor or Kata Containers add an additional isolation layer that intercepts system calls or runs containers in lightweight VMs.

## How to Fix

Specify a sandboxed RuntimeClass in the pod spec:

```yaml
spec:
  runtimeClassName: gvisor
```

Available RuntimeClasses depend on your cluster configuration. Common options include `gvisor` (user-space kernel), `kata` (micro-VMs), and `firecracker`. Check your cluster's available RuntimeClasses with `kubectl get runtimeclasses`.

## Learn More

Sandboxed runtimes are especially important for multi-tenant clusters and workloads processing untrusted input. They add latency overhead, so evaluate performance requirements. See the Kubernetes RuntimeClass documentation.

**Affected resources:** kv-e2e-secrets/Deployment/app-with-hardcoded-secrets, kv-e2e-secrets/Pod/app-with-secret-env

</details>

<details>
<summary>Remediation: topology-spread (2 resources affected)</summary>

## Why This Matters

Without topology spread constraints, the scheduler may place all replicas on the same node or in the same availability zone. If that node or zone fails, your entire service goes down despite having multiple replicas. This negates the high-availability benefits of running multiple pods.

## How to Fix

Add topology spread constraints to distribute replicas across failure domains:

```yaml
spec:
  topologySpreadConstraints:
    - maxSkew: 1
      topologyKey: kubernetes.io/hostname
      whenUnsatisfiable: DoNotSchedule
      labelSelector:
        matchLabels:
          app: my-app
    - maxSkew: 1
      topologyKey: topology.kubernetes.io/zone
      whenUnsatisfiable: ScheduleAnyway
```

Use `kubernetes.io/hostname` for node-level spreading and `topology.kubernetes.io/zone` for zone-level spreading.

## Learn More

See the Kubernetes Pod Topology Spread Constraints documentation. Combining hostname and zone constraints provides both node-level and zone-level fault tolerance.

**Affected resources:** kv-e2e-secrets/Deployment/app-with-hardcoded-secrets, kv-e2e-secrets/Pod/app-with-secret-env

</details>

<details>
<summary>Remediation: secrets-default-type (3 resources affected)</summary>

## Why This Matters

Kubernetes provides built-in Secret types (e.g., kubernetes.io/tls, kubernetes.io/basic-auth) that enforce required key names and enable automatic validation. Using the generic Opaque type bypasses these guardrails, making misconfigurations harder to catch and reducing interoperability with tools like cert-manager, Ingress controllers, and kubectl.

## How to Fix

Change the Secret type to the recommended built-in type:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-secret
type: kubernetes.io/basic-auth    # Use the specific type
```

Kubernetes will validate that the required data keys are present for the chosen type.

## Learn More

See the Kubernetes Secret types documentation for the full list of built-in types and their required keys. CIS Benchmark recommends using typed secrets for better auditability.

**Affected resources:** kv-e2e-secrets/Secret/db-auth-opaque, kv-e2e-secrets/Secret/db-credentials, kv-e2e-secrets/Secret/tls-cert-opaque

</details>

<details>
<summary>Remediation: limit-range-missing (1 resources affected)</summary>

## Why This Matters

Without a LimitRange, any container can be created without resource constraints. A single runaway or malicious pod can consume all node CPU and memory, causing denial of service for other workloads on the same node.

## How to Fix

Create a LimitRange in the namespace to set default and maximum resource constraints:

```yaml
apiVersion: v1
kind: LimitRange
metadata:
  name: default-limits
  namespace: my-app
spec:
  limits:
    - type: Container
      default:
        cpu: 500m
        memory: 256Mi
      defaultRequest:
        cpu: 100m
        memory: 128Mi
      max:
        cpu: "2"
        memory: 1Gi
```

Containers that omit resource requests/limits will inherit these defaults automatically.

## Learn More

CIS Kubernetes Benchmark 5.2.1 recommends LimitRanges for resource governance. See https://kubernetes.io/docs/concepts/policy/limit-range/ for configuration details.

**Affected resources:** kv-e2e-secrets/Namespace/kv-e2e-secrets

</details>

<details>
<summary>Remediation: resource-quota-missing (1 resources affected)</summary>

## Why This Matters

Without a ResourceQuota, a single namespace can consume the entire cluster's CPU, memory, and storage. This creates a noisy-neighbor problem where one team's workloads starve others, and makes capacity planning impossible.

## How to Fix

Create a ResourceQuota to cap the namespace's total resource consumption:

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: compute-quota
  namespace: my-app
spec:
  hard:
    requests.cpu: "10"
    requests.memory: 20Gi
    limits.cpu: "20"
    limits.memory: 40Gi
    pods: "50"
    services: "10"
```

Tune quota values based on the namespace's actual workload requirements and cluster capacity.

## Learn More

CIS Kubernetes Benchmark 5.2.2 recommends ResourceQuotas for multi-tenant clusters. See https://kubernetes.io/docs/concepts/policy/resource-quotas/ for quota configuration and enforcement behavior.

**Affected resources:** kv-e2e-secrets/Namespace/kv-e2e-secrets

</details>

### kv-e2e-storage (56 findings — 🟠9 🟡30 🔵17)

| Severity | Check | Resources | Message | Frameworks |
|----------|-------|-----------|---------|-----------|
| 🟠 High | automount-token | **2 resources** | Deployment "emptydir-no-limit" auto-mounts a ServiceAccount token. Most workloads do not need Kubernetes API access. | CIS 5.1.6 · MITRE T1552.007 · NSA 3.2 |
| 🟠 High | default-service-account | **2 resources** | Deployment "emptydir-no-limit" uses the default ServiceAccount, which may have unintended permissions. | CIS 5.1.5 · CIS 5.1.6 · MITRE T1078.001 · NSA 3.1 · NSA 3.2 |
| 🟠 High | privilege-escalation | **2 resources** | Container "pause" does not set allowPrivilegeEscalation to false, permitting privilege escalation. | CIS 5.2.6 · MITRE T1068 · MITRE T1611 · NSA 1.1 · NSA 2.1 |
| 🟠 High | run-as-root | **2 resources** | Container "pause" does not set runAsNonRoot: true and may run as root. | CIS 5.2.7 · MITRE T1611 · NSA 1.1 |
| 🟠 High | network-policy-missing | kv-e2e-storage/Namespace/kv-e2e-storage | Namespace "kv-e2e-storage" has no NetworkPolicy defined. All pods are unrestricted. | CIS 5.3.2 · MITRE T1046 · NSA 4.1 · NSA 4.2 |
| 🟡 Medium | pvc-no-encryption | **3 resources** | PVC "data-no-sc" uses StorageClass "standard" which has no encryption configuration. | CIS 5.4.2 · MITRE T1530 · NSA 5.2 |
| 🟡 Medium | apparmor-profile | **2 resources** | Container "pause" does not have an AppArmor profile set. | CIS 5.6.3 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | capabilities-not-dropped | **2 resources** | Container "pause" does not drop ALL capabilities, leaving it with unnecessary default privileges. | CIS 5.2.8 · CIS 5.2.10 · MITRE T1068 · NSA 1.1 |
| 🟡 Medium | image-pull-policy | **2 resources** | Container "pause" uses a mutable image tag with pullPolicy "IfNotPresent" (image: registry.k8s.io/pause:3.9), risking stale images. | CIS 5.5.1 · MITRE T1525 · NSA 1.4 |
| 🟡 Medium | psa-restricted-violations | **6 resources** | Deployment "emptydir-no-limit" container "pause" violates PSS Restricted: runAsNonRoot is not true. | CIS 5.2.1 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | read-only-rootfs | **2 resources** | Container "pause" does not have a read-only root filesystem. | CIS 5.6.3 · MITRE T1565.001 · NSA 1.2 |
| 🟡 Medium | resource-limits-missing | **2 resources** | Container "pause" is missing both CPU and memory limits. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🟡 Medium | resource-requests-missing | **2 resources** | Container "pause" is missing both CPU and memory requests. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🟡 Medium | run-as-group | **2 resources** | Container "pause" does not set runAsGroup; the process will run as GID 0 (root group) by default. | CIS 5.2.7 · MITRE T1068 · NSA 1.1 |
| 🟡 Medium | seccomp-profile | **2 resources** | Container "pause" does not have a Seccomp profile set at either the container or pod level. | CIS 5.6.2 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | token-projection-config | kv-e2e-storage/Deployment/emptydir-no-limit | Deployment "emptydir-no-limit" does not use explicitly configured projected ServiceAccount tokens with expiry and audience restrictions. | CIS 5.1.6 · MITRE T1552.007 · NSA 3.2 |
| 🟡 Medium | network-policy-egress-unrestricted | kv-e2e-storage/Namespace/kv-e2e-storage | Namespace "kv-e2e-storage" has no NetworkPolicy with egress restrictions. Pods can reach any external destination. | CIS 5.3.2 · MITRE T1048 · NSA 4.2 |
| 🟡 Medium | psa-labels-missing | kv-e2e-storage/Namespace/kv-e2e-storage | Namespace "kv-e2e-storage" is missing the pod-security.kubernetes.io/enforce label; pod security is not enforced. | CIS 5.2.1 · MITRE T1610 · NSA 2.1 |
| 🟡 Medium | projected-volume-security | **2 resources** | Pod "projected-permissive" has projected volume "sa-token" with defaultMode 0644 which is too permissive. | CIS 5.4.1 · MITRE T1552 · NSA 5.1 |
| 🔵 Low | emptydir-size-limit | kv-e2e-storage/Deployment/emptydir-no-limit | Deployment "emptydir-no-limit" has emptyDir volume "scratch" without sizeLimit; a container can fill the node disk. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | ephemeral-storage-limits | **2 resources** | Container "pause" is missing ephemeral-storage limits. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | image-no-digest | **2 resources** | Container "pause" image is not pinned by digest (image: registry.k8s.io/pause:3.9), allowing tag mutation. | CIS 5.5.1 · MITRE T1525 · NSA 1.4 |
| 🔵 Low | liveness-readiness-probes | **4 resources** | Container "pause" has no liveness probe configured. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | priority-class-missing | **2 resources** | Deployment "emptydir-no-limit" has no PriorityClass set; it will be evicted first during resource pressure. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | runtime-class | **2 resources** | Pod "emptydir-no-limit" does not specify a RuntimeClass, using the default (unsandboxed) runtime. | CIS 5.6.3 · MITRE T1611 · NSA 2.1 |
| 🔵 Low | topology-spread | **2 resources** | Deployment "emptydir-no-limit" has no topology spread constraints; all replicas may be scheduled on the same node. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | limit-range-missing | kv-e2e-storage/Namespace/kv-e2e-storage | Namespace "kv-e2e-storage" has no LimitRange defined. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | resource-quota-missing | kv-e2e-storage/Namespace/kv-e2e-storage | Namespace "kv-e2e-storage" has no ResourceQuota defined. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |

<details>
<summary>automount-token: 2 affected resources</summary>

- `kv-e2e-storage/Deployment/emptydir-no-limit`
- `kv-e2e-storage/Pod/projected-permissive`

</details>

<details>
<summary>default-service-account: 2 affected resources</summary>

- `kv-e2e-storage/Deployment/emptydir-no-limit`
- `kv-e2e-storage/Pod/projected-permissive`

</details>

<details>
<summary>privilege-escalation: 2 affected resources</summary>

- `kv-e2e-storage/Deployment/emptydir-no-limit (pause)`
- `kv-e2e-storage/Pod/projected-permissive (pause)`

</details>

<details>
<summary>run-as-root: 2 affected resources</summary>

- `kv-e2e-storage/Deployment/emptydir-no-limit (pause)`
- `kv-e2e-storage/Pod/projected-permissive (pause)`

</details>

<details>
<summary>pvc-no-encryption: 3 affected resources</summary>

- `kv-e2e-storage/PersistentVolumeClaim/data-no-sc`
- `kv-e2e-storage/PersistentVolumeClaim/hostpath-claim`
- `kv-e2e-storage/PersistentVolumeClaim/shared-data-rwx`

</details>

<details>
<summary>apparmor-profile: 2 affected resources</summary>

- `kv-e2e-storage/Deployment/emptydir-no-limit (pause)`
- `kv-e2e-storage/Pod/projected-permissive (pause)`

</details>

<details>
<summary>capabilities-not-dropped: 2 affected resources</summary>

- `kv-e2e-storage/Deployment/emptydir-no-limit (pause)`
- `kv-e2e-storage/Pod/projected-permissive (pause)`

</details>

<details>
<summary>image-pull-policy: 2 affected resources</summary>

- `kv-e2e-storage/Deployment/emptydir-no-limit (pause)`
- `kv-e2e-storage/Pod/projected-permissive (pause)`

</details>

<details>
<summary>psa-restricted-violations: 6 affected resources</summary>

- `kv-e2e-storage/Deployment/emptydir-no-limit (pause)`
- `kv-e2e-storage/Deployment/emptydir-no-limit (pause)`
- `kv-e2e-storage/Deployment/emptydir-no-limit (pause)`
- `kv-e2e-storage/Pod/projected-permissive (pause)`
- `kv-e2e-storage/Pod/projected-permissive (pause)`
- `kv-e2e-storage/Pod/projected-permissive (pause)`

</details>

<details>
<summary>read-only-rootfs: 2 affected resources</summary>

- `kv-e2e-storage/Deployment/emptydir-no-limit (pause)`
- `kv-e2e-storage/Pod/projected-permissive (pause)`

</details>

<details>
<summary>resource-limits-missing: 2 affected resources</summary>

- `kv-e2e-storage/Deployment/emptydir-no-limit (pause)`
- `kv-e2e-storage/Pod/projected-permissive (pause)`

</details>

<details>
<summary>resource-requests-missing: 2 affected resources</summary>

- `kv-e2e-storage/Deployment/emptydir-no-limit (pause)`
- `kv-e2e-storage/Pod/projected-permissive (pause)`

</details>

<details>
<summary>run-as-group: 2 affected resources</summary>

- `kv-e2e-storage/Deployment/emptydir-no-limit (pause)`
- `kv-e2e-storage/Pod/projected-permissive (pause)`

</details>

<details>
<summary>seccomp-profile: 2 affected resources</summary>

- `kv-e2e-storage/Deployment/emptydir-no-limit (pause)`
- `kv-e2e-storage/Pod/projected-permissive (pause)`

</details>

<details>
<summary>projected-volume-security: 2 affected resources</summary>

- `kv-e2e-storage/Pod/projected-permissive`
- `kv-e2e-storage/Pod/projected-permissive`

</details>

<details>
<summary>ephemeral-storage-limits: 2 affected resources</summary>

- `kv-e2e-storage/Deployment/emptydir-no-limit (pause)`
- `kv-e2e-storage/Pod/projected-permissive (pause)`

</details>

<details>
<summary>image-no-digest: 2 affected resources</summary>

- `kv-e2e-storage/Deployment/emptydir-no-limit (pause)`
- `kv-e2e-storage/Pod/projected-permissive (pause)`

</details>

<details>
<summary>liveness-readiness-probes: 4 affected resources</summary>

- `kv-e2e-storage/Deployment/emptydir-no-limit (pause)`
- `kv-e2e-storage/Deployment/emptydir-no-limit (pause)`
- `kv-e2e-storage/Pod/projected-permissive (pause)`
- `kv-e2e-storage/Pod/projected-permissive (pause)`

</details>

<details>
<summary>priority-class-missing: 2 affected resources</summary>

- `kv-e2e-storage/Deployment/emptydir-no-limit`
- `kv-e2e-storage/Pod/projected-permissive`

</details>

<details>
<summary>runtime-class: 2 affected resources</summary>

- `kv-e2e-storage/Deployment/emptydir-no-limit`
- `kv-e2e-storage/Pod/projected-permissive`

</details>

<details>
<summary>topology-spread: 2 affected resources</summary>

- `kv-e2e-storage/Deployment/emptydir-no-limit`
- `kv-e2e-storage/Pod/projected-permissive`

</details>

<details>
<summary>Remediation: automount-token (2 resources affected)</summary>

## Why This Matters

When a ServiceAccount token is auto-mounted, every container in the pod can call the Kubernetes API. If a container is compromised through a vulnerability or misconfiguration, the attacker gains API access to enumerate resources, read secrets, or escalate privileges.

## How to Fix

Disable auto-mounting at the pod spec level for workloads that do not need API access:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      automountServiceAccountToken: false
      containers:
        - name: app
          image: my-app:latest
```

For workloads that do require API access, use projected tokens with bounded lifetime and audience restrictions instead of the default long-lived token.

## Learn More

Refer to the Kubernetes documentation on configuring service accounts for pods and CIS Kubernetes Benchmark 5.1.6 for auto-mount token guidance.

**Affected resources:** kv-e2e-storage/Deployment/emptydir-no-limit, kv-e2e-storage/Pod/projected-permissive

</details>

<details>
<summary>Remediation: default-service-account (2 resources affected)</summary>

## Why This Matters

The default ServiceAccount is shared by every pod in a namespace. If any pod is compromised, the attacker inherits whatever permissions have been granted to the default account via role bindings, enabling lateral movement across all workloads sharing it.

## How to Fix

Create a dedicated ServiceAccount for each workload and reference it in the pod spec:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-app
  namespace: production
automountServiceAccountToken: false
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      serviceAccountName: my-app
```

Grant only the permissions the workload actually needs via a dedicated Role and RoleBinding.

## Learn More

See the Kubernetes documentation on managing service accounts and CIS Kubernetes Benchmark 5.1.5 for guidance on ensuring default service accounts are not actively used.

**Affected resources:** kv-e2e-storage/Deployment/emptydir-no-limit, kv-e2e-storage/Pod/projected-permissive

</details>

<details>
<summary>Remediation: privilege-escalation (2 resources affected)</summary>

## Why This Matters

By default, Kubernetes allows containers to escalate privileges via setuid/setgid binaries, which let a process gain more permissions than its parent. An attacker can exploit this using setuid binaries already present in the container image (like `su`, `sudo`, or `ping`) to elevate from a low-privilege user to root.

## How to Fix

Explicitly disable privilege escalation in the container's securityContext:

```yaml
securityContext:
  allowPrivilegeEscalation: false
  runAsNonRoot: true
  capabilities:
    drop: ["ALL"]
```

This blocks the use of setuid/setgid binaries and prevents the no_new_privs Linux flag from being cleared. The vast majority of application containers do not need privilege escalation.

## Learn More

This is required by the Pod Security Standards "Restricted" profile and CIS Benchmark 5.2.5. Disabling privilege escalation is one of the most impactful single-line security improvements you can make.

**Affected resources:** kv-e2e-storage/Deployment/emptydir-no-limit, kv-e2e-storage/Pod/projected-permissive

</details>

<details>
<summary>Remediation: run-as-root (2 resources affected)</summary>

## Why This Matters

Without `runAsNonRoot: true`, Kubernetes does not enforce non-root execution and the container may default to running as UID 0 depending on the image's USER directive. If the image defaults to root, the container process gains full privileges, increasing the blast radius of any compromise or container escape.

## How to Fix

Enforce non-root execution in the securityContext:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
```

With `runAsNonRoot: true`, Kubernetes will reject the pod at admission time if the container image attempts to run as root. Setting an explicit `runAsUser` provides an additional guarantee.

## Learn More

This aligns with CIS Benchmark 5.2.6 and the Pod Security Standards "Restricted" profile. The `runAsNonRoot` field acts as a safety net even when images change their default USER.

**Affected resources:** kv-e2e-storage/Deployment/emptydir-no-limit, kv-e2e-storage/Pod/projected-permissive

</details>

<details>
<summary>Remediation: network-policy-missing (1 resources affected)</summary>

## Why This Matters

Without NetworkPolicies, every pod in this namespace can communicate freely with every other pod in the cluster. If an attacker compromises a single pod, they can move laterally to databases, internal APIs, and other sensitive services with no network-level barriers.

## How to Fix

Create a default-deny NetworkPolicy for the namespace, then add targeted allow rules for legitimate traffic:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: my-namespace
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
```

After applying the default-deny, create additional NetworkPolicy resources that whitelist only the specific ingress and egress flows your workloads require.

## Learn More

See the Kubernetes documentation on NetworkPolicies and CIS Kubernetes Benchmark 5.3.2. A CNI plugin that supports NetworkPolicy (Calico, Cilium, Weave Net) must be installed for policies to take effect.

**Affected resources:** kv-e2e-storage/Namespace/kv-e2e-storage

</details>

<details>
<summary>Remediation: pvc-no-encryption (3 resources affected)</summary>

## Why This Matters

PVCs without encryption store data in plaintext on the underlying disk. If the storage media is decommissioned, stolen, or accessed by an unauthorized party, all data is readable. This is especially critical for volumes storing credentials, PII, or financial data.

## How to Fix

Create a StorageClass with encryption enabled and reference it in your PVC:

```yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: encrypted-gp3
provisioner: ebs.csi.aws.com
parameters:
  encrypted: "true"
  kmsKeyId: arn:aws:kms:...:key/...   # Optional: customer-managed key
---
apiVersion: v1
kind: PersistentVolumeClaim
spec:
  storageClassName: encrypted-gp3
```

Each cloud provider has its own encryption parameter: AWS EBS (`encrypted: "true"`), GCP PD (CMEK via `disk-encryption-kms-key`), Azure Disk (SSE enabled by default).

## Learn More

See your cloud provider's CSI driver documentation for encryption configuration. The CIS Kubernetes Benchmark recommends encrypting persistent volumes at rest.

**Affected resources:** kv-e2e-storage/PersistentVolumeClaim/data-no-sc, kv-e2e-storage/PersistentVolumeClaim/hostpath-claim, kv-e2e-storage/PersistentVolumeClaim/shared-data-rwx

</details>

<details>
<summary>Remediation: apparmor-profile (2 resources affected)</summary>

## Why This Matters

AppArmor provides mandatory access control (MAC) that restricts which files, network resources, and capabilities a container process can access. Without an AppArmor profile, the container operates without these restrictions, allowing an attacker with code execution to access any file the container user can read and make unrestricted network connections.

## How to Fix

Apply an AppArmor profile in the container's securityContext (Kubernetes 1.30+):

```yaml
securityContext:
  appArmorProfile:
    type: RuntimeDefault
```

The RuntimeDefault profile provides sensible restrictions for most applications. For tighter control, create a custom Localhost profile that only allows the specific file and network access your application needs.

## Learn More

AppArmor is available on Debian/Ubuntu-based nodes. RHEL/CentOS nodes use SELinux instead. Both provide MAC enforcement. Refer to CIS Benchmark 5.7.5 and the Kubernetes AppArmor documentation.

**Affected resources:** kv-e2e-storage/Deployment/emptydir-no-limit, kv-e2e-storage/Pod/projected-permissive

</details>

<details>
<summary>Remediation: capabilities-not-dropped (2 resources affected)</summary>

## Why This Matters

By default, containers receive a set of Linux capabilities including KILL, SETUID, SETGID, and NET_RAW. These defaults are rarely needed by application code and significantly increase the potential damage from a container compromise. Dropping all capabilities follows the principle of least privilege.

## How to Fix

Explicitly drop all capabilities and selectively add back only what your application needs:

```yaml
securityContext:
  capabilities:
    drop: ["ALL"]
    add: ["NET_BIND_SERVICE"]  # Only if needed
```

Most web applications, API servers, and background workers run perfectly with all capabilities dropped. Test your application after making this change to confirm no functionality is lost.

## Learn More

This is required by the Pod Security Standards "Restricted" profile and aligns with CIS Benchmark 5.2.7. Kubernetes best practice is to treat capability grants as exceptions that require explicit justification.

**Affected resources:** kv-e2e-storage/Deployment/emptydir-no-limit, kv-e2e-storage/Pod/projected-permissive

</details>

<details>
<summary>Remediation: image-pull-policy (2 resources affected)</summary>

## Why This Matters

When a mutable image tag is used without `imagePullPolicy: Always`, Kubernetes may serve a cached version of the image from the node. If the tag has been updated in the registry (with a security patch or -- worse -- a compromised layer), the running container will not reflect those changes.

## How to Fix

Set `imagePullPolicy: Always` for any container using a mutable tag:

```yaml
containers:
  - name: app
    image: nginx:1.25.3
    imagePullPolicy: Always   # Forces fresh pull each time
```

Alternatively, pin images by digest (`image@sha256:...`), which makes the pull policy irrelevant because the content is immutable.

## Learn More

See the Kubernetes documentation on image pull policies and CIS Kubernetes Benchmark 5.4.2 for pull policy guidance.

**Affected resources:** kv-e2e-storage/Deployment/emptydir-no-limit, kv-e2e-storage/Pod/projected-permissive

</details>

<details>
<summary>Remediation: psa-restricted-violations (6 resources affected)</summary>

## Why This Matters

Running as root inside a container means that any container escape vulnerability immediately grants root access on the host node. Even without an escape, root inside the container can modify sensitive files, install packages, and access capabilities that non-root users cannot.

## How to Fix

Set `runAsNonRoot: true` and specify a non-root user ID in the security context:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
```

Set this at the pod level to apply to all containers. Ensure your container image supports running as a non-root user (many official images do).

## Learn More

See the Pod Security Standards Restricted profile and CIS Kubernetes Benchmark 5.2.6. Running as non-root is a fundamental container security best practice.

**Affected resources:** kv-e2e-storage/Deployment/emptydir-no-limit, kv-e2e-storage/Deployment/emptydir-no-limit, kv-e2e-storage/Deployment/emptydir-no-limit, kv-e2e-storage/Pod/projected-permissive, kv-e2e-storage/Pod/projected-permissive, kv-e2e-storage/Pod/projected-permissive

</details>

<details>
<summary>Remediation: read-only-rootfs (2 resources affected)</summary>

## Why This Matters

A writable root filesystem allows an attacker who gains code execution in your container to modify application binaries, install attack tools, plant backdoors, or persist malware across container restarts. Making the filesystem read-only eliminates an entire class of post-exploitation techniques.

## How to Fix

Enable a read-only root filesystem and mount writable volumes only where needed:

```yaml
securityContext:
  readOnlyRootFilesystem: true
volumeMounts:
  - name: tmp
    mountPath: /tmp
volumes:
  - name: tmp
    emptyDir: {}
```

Common paths that need write access include /tmp, /var/cache, and /var/run. Mount each as an emptyDir or tmpfs volume rather than making the entire filesystem writable.

## Learn More

This aligns with CIS Benchmark 5.2.4 and the defense-in-depth principle. Combined with dropping capabilities and running as non-root, a read-only filesystem forms a strong container hardening baseline.

**Affected resources:** kv-e2e-storage/Deployment/emptydir-no-limit, kv-e2e-storage/Pod/projected-permissive

</details>

<details>
<summary>Remediation: resource-limits-missing (2 resources affected)</summary>

## Why This Matters

Without resource limits, a single container can consume all available CPU and memory on a node, starving other workloads and triggering cascading failures. An attacker who compromises an unlimited container can mount a denial-of-service attack against the entire node with a simple fork bomb or memory allocation loop.

## How to Fix

Set both CPU and memory limits based on your application's actual resource usage:

```yaml
resources:
  limits:
    cpu: 500m
    memory: 256Mi
  requests:
    cpu: 100m
    memory: 128Mi
```

Profile your application under load to determine appropriate values. Set limits to handle peak usage and requests to match steady-state consumption.

## Learn More

Use LimitRange objects to enforce default limits at the namespace level. Resource limits also determine the pod's QoS class: pods with equal requests and limits get Guaranteed QoS and are last to be evicted.

**Affected resources:** kv-e2e-storage/Deployment/emptydir-no-limit, kv-e2e-storage/Pod/projected-permissive

</details>

<details>
<summary>Remediation: resource-requests-missing (2 resources affected)</summary>

## Why This Matters

Resource requests tell the Kubernetes scheduler how much CPU and memory your container needs. Without requests, the scheduler treats the pod as needing zero resources and may pack too many pods onto a single node. This leads to overcommitment, resource contention, throttling, and OOM kills under load.

## How to Fix

Set resource requests based on your application's steady-state usage:

```yaml
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 256Mi
```

Observe your application's actual resource consumption using `kubectl top` or a monitoring tool, then set requests to match the typical steady-state usage.

## Learn More

Resource requests determine the pod's QoS class and scheduling behavior. Pods with requests equal to limits receive Guaranteed QoS. Use Vertical Pod Autoscaler (VPA) to automatically recommend request values.

**Affected resources:** kv-e2e-storage/Deployment/emptydir-no-limit, kv-e2e-storage/Pod/projected-permissive

</details>

<details>
<summary>Remediation: run-as-group (2 resources affected)</summary>

## Why This Matters

Without an explicit runAsGroup, the container process defaults to GID 0 (the root group). Files and sockets owned by the root group become accessible to the container, including potentially sensitive host files if volumes are mounted. This widens the attack surface unnecessarily.

## How to Fix

Set an explicit non-root group in the securityContext:

```yaml
securityContext:
  runAsGroup: 1000
  runAsUser: 1000
  runAsNonRoot: true
```

Ensure the container image's application files and directories are readable by the specified GID. You may need to adjust file ownership in your Dockerfile with `chown`.

## Learn More

This aligns with CIS Benchmark 5.2.6 and the Pod Security Standards "Restricted" profile. Always set runAsUser, runAsGroup, and runAsNonRoot together for comprehensive identity control.

**Affected resources:** kv-e2e-storage/Deployment/emptydir-no-limit, kv-e2e-storage/Pod/projected-permissive

</details>

<details>
<summary>Remediation: seccomp-profile (2 resources affected)</summary>

## Why This Matters

Without a Seccomp profile, containers can invoke any of the 300+ Linux system calls, leaving the entire kernel attack surface exposed. Kernel vulnerabilities in obscure syscalls are a primary vector for container escapes. Seccomp filtering blocks dangerous syscalls that legitimate applications never use.

## How to Fix

Apply a Seccomp profile at the container or pod level:

```yaml
securityContext:
  seccompProfile:
    type: RuntimeDefault
```

The RuntimeDefault profile blocks approximately 50 dangerous syscalls while allowing normal application behavior. For stricter controls, use a custom Localhost profile tailored to your application's needs. Set the profile at the pod level to apply it to all containers.

## Learn More

Seccomp profiles are required by the Pod Security Standards "Restricted" profile and CIS Benchmark 5.7.2. Use tools like `strace` or the Security Profiles Operator to generate custom profiles for your workloads.

**Affected resources:** kv-e2e-storage/Deployment/emptydir-no-limit, kv-e2e-storage/Pod/projected-permissive

</details>

<details>
<summary>Remediation: token-projection-config (1 resources affected)</summary>

## Why This Matters

Without explicit projection configuration, ServiceAccount tokens use Kubernetes defaults: no audience restriction and a long expiration. A stolen token remains valid for an extended period and can be used against any API server endpoint, widening the blast radius of a compromise.

## How to Fix

Add a projected volume with explicit expiration and audience:

```yaml
spec:
  volumes:
    - name: token
      projected:
        sources:
          - serviceAccountToken:
              expirationSeconds: 3600
              audience: my-api
              path: token
  containers:
    - name: app
      volumeMounts:
        - name: token
          mountPath: /var/run/secrets/tokens
          readOnly: true
```

Projected tokens auto-rotate before expiry and are rejected by endpoints outside the specified audience.

## Learn More

See the Kubernetes documentation on projected volumes and service account token volume projection for detailed configuration options.

**Affected resources:** kv-e2e-storage/Deployment/emptydir-no-limit

</details>

<details>
<summary>Remediation: network-policy-egress-unrestricted (1 resources affected)</summary>

## Why This Matters

Without any egress NetworkPolicy in this namespace, pods can freely send traffic to any destination including the public internet. A compromised pod can exfiltrate sensitive data, reach cloud metadata services (e.g., 169.254.169.254), or establish reverse shells to attacker-controlled servers.

## How to Fix

Create a NetworkPolicy with `Egress` in `policyTypes` to restrict outbound traffic. At minimum, allow DNS resolution:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-egress
  namespace: my-namespace
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector: {}
      ports:
        - port: 53
          protocol: UDP
```

Add additional egress rules for specific services your workloads need to reach.

## Learn More

See the Kubernetes NetworkPolicy documentation and CIS Kubernetes Benchmark 5.3.2. Egress controls are a key defense-in-depth measure recommended by the NSA/CISA Kubernetes Hardening Guide.

**Affected resources:** kv-e2e-storage/Namespace/kv-e2e-storage

</details>

<details>
<summary>Remediation: psa-labels-missing (1 resources affected)</summary>

## Why This Matters

Without PSA enforcement labels, any pod configuration is allowed in this namespace, including privileged containers, host namespace access, and root execution. This bypasses Kubernetes' built-in Pod Security Standards and leaves the namespace vulnerable to workloads that could compromise the node.

## How to Fix

Add Pod Security Admission labels to enforce a security profile on all pods in the namespace:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: kv-e2e-storage
  labels:
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

Start with `baseline` enforcement to block known privilege escalations, then upgrade to `restricted` after verifying all workloads are compliant.

## Learn More

See the Kubernetes Pod Security Admission documentation and CIS Kubernetes Benchmark 5.2. The three-tier approach (enforce, audit, warn) allows gradual adoption of stricter profiles.

**Affected resources:** kv-e2e-storage/Namespace/kv-e2e-storage

</details>

<details>
<summary>Remediation: projected-volume-security (2 resources affected)</summary>

## Why This Matters

Projected volumes with overly permissive file modes allow any process in the pod to read sensitive data such as service account tokens and secrets. If a container is compromised, the attacker can easily harvest these credentials to escalate privileges or move laterally within the cluster.

## How to Fix

Reduce the defaultMode to restrict file access:

```yaml
spec:
  volumes:
    - name: sa-token
      projected:
        defaultMode: 0400         # Owner read-only (was too permissive)
        sources:
          - serviceAccountToken:
              path: token
```

Use 0400 for read-only access or 0600 if the application must write to the mounted files.

## Learn More

See the Kubernetes Projected Volumes documentation for defaultMode details. The CIS Benchmark recommends file modes of 0600 or lower for sensitive volume mounts to limit exposure within the pod.

**Affected resources:** kv-e2e-storage/Pod/projected-permissive, kv-e2e-storage/Pod/projected-permissive

</details>

<details>
<summary>Remediation: emptydir-size-limit (1 resources affected)</summary>

## Why This Matters

An emptyDir volume without a sizeLimit allows a container to write unlimited data to the node's filesystem. A compromised or misbehaving container can fill the entire node disk, causing kubelet failures, pod evictions, and node instability that affects all workloads on that node.

## How to Fix

Set a sizeLimit on the emptyDir volume based on expected usage:

```yaml
spec:
  volumes:
    - name: scratch
      emptyDir:
        sizeLimit: 1Gi           # Set to expected max usage
        medium: ""               # Or Memory for tmpfs
```

When the limit is exceeded, the pod will be evicted. Size conservatively and monitor actual usage to tune the limit.

## Learn More

See the Kubernetes Volumes documentation on emptyDir. Setting sizeLimit is a defense-in-depth measure that protects node stability alongside resource quotas and LimitRanges.

**Affected resources:** kv-e2e-storage/Deployment/emptydir-no-limit

</details>

<details>
<summary>Remediation: ephemeral-storage-limits (2 resources affected)</summary>

## Why This Matters

Ephemeral storage includes container logs, emptyDir volumes, and the writable container layer. Without limits, a single container can fill the node's root disk, triggering eviction of all pods on that node and potentially causing a cascading failure across your cluster. This is a common denial-of-service vector.

## How to Fix

Set ephemeral-storage limits alongside your CPU and memory limits:

```yaml
resources:
  limits:
    ephemeral-storage: 1Gi
  requests:
    ephemeral-storage: 500Mi
```

Estimate your application's disk usage from logs, temporary files, and cache data. If your application writes large temporary files, consider using a PersistentVolumeClaim instead of ephemeral storage.

## Learn More

The kubelet evicts pods that exceed their ephemeral-storage limit. Use LimitRange to set default ephemeral-storage limits at the namespace level to catch containers that omit this setting.

**Affected resources:** kv-e2e-storage/Deployment/emptydir-no-limit, kv-e2e-storage/Pod/projected-permissive

</details>

<details>
<summary>Remediation: image-no-digest (2 resources affected)</summary>

## Why This Matters

Image tags are mutable pointers -- a registry administrator or attacker can re-push a different image under the same tag. Without a digest, you have no cryptographic guarantee that the image you deploy is the one you tested.

## How to Fix

Pin images by their SHA-256 content digest for a fully immutable reference:

```yaml
containers:
  - name: app
    image: nginx@sha256:a8281ce420348a01ea6e   # Immutable
```

Use `crane digest nginx:1.25.3` or `skopeo inspect` to resolve a tag to its digest during CI/CD, then commit the pinned reference.

## Learn More

SLSA Level 1+ and NIST SP 800-190 recommend digest pinning for container supply chain integrity. See the Kubernetes images documentation for details.

**Affected resources:** kv-e2e-storage/Deployment/emptydir-no-limit, kv-e2e-storage/Pod/projected-permissive

</details>

<details>
<summary>Remediation: liveness-readiness-probes (4 resources affected)</summary>

## Why This Matters

Without a liveness probe, Kubernetes cannot detect when a container has become unresponsive or deadlocked. The container continues running and consuming resources while failing to serve traffic. Users experience timeouts and errors until someone manually intervenes.

## How to Fix

Add a liveness probe that checks the container's health:

```yaml
containers:
  - name: app
    livenessProbe:
      httpGet:
        path: /healthz
        port: 8080
      initialDelaySeconds: 15
      periodSeconds: 10
      failureThreshold: 3
```

Use `httpGet` for HTTP services, `tcpSocket` for TCP services, or `exec` with a custom health check script for non-network workloads.

## Learn More

See the Kubernetes documentation on container probes. Set initialDelaySeconds high enough for your application to start, and consider adding a startupProbe for slow-starting containers.

**Affected resources:** kv-e2e-storage/Deployment/emptydir-no-limit, kv-e2e-storage/Deployment/emptydir-no-limit, kv-e2e-storage/Pod/projected-permissive, kv-e2e-storage/Pod/projected-permissive

</details>

<details>
<summary>Remediation: priority-class-missing (2 resources affected)</summary>

## Why This Matters

Without a PriorityClass, pods receive default priority (typically 0) and are among the first to be evicted during resource pressure or node maintenance. This means important application workloads may be killed before less critical ones, leading to unpredictable outages.

## How to Fix

Define PriorityClasses for your workloads and assign them appropriately:

```yaml
apiVersion: scheduling.k8s.io/v1
kind: PriorityClass
metadata:
  name: app-medium
value: 100000
---
# Reference in your workload:
spec:
  priorityClassName: app-medium
```

Create a tiered priority scheme (e.g., app-critical: 500000, app-medium: 100000, app-low: 10000) that reflects your workload importance hierarchy.

## Learn More

Refer to the Kubernetes Pod Priority and Preemption documentation. Establishing a consistent priority scheme across namespaces ensures predictable eviction behavior during resource contention.

**Affected resources:** kv-e2e-storage/Deployment/emptydir-no-limit, kv-e2e-storage/Pod/projected-permissive

</details>

<details>
<summary>Remediation: runtime-class (2 resources affected)</summary>

## Why This Matters

Without a RuntimeClass, pods use the default container runtime (typically runc), which shares the host kernel directly with containers. A kernel vulnerability can allow container escape to the host. Sandboxed runtimes like gVisor or Kata Containers add an additional isolation layer that intercepts system calls or runs containers in lightweight VMs.

## How to Fix

Specify a sandboxed RuntimeClass in the pod spec:

```yaml
spec:
  runtimeClassName: gvisor
```

Available RuntimeClasses depend on your cluster configuration. Common options include `gvisor` (user-space kernel), `kata` (micro-VMs), and `firecracker`. Check your cluster's available RuntimeClasses with `kubectl get runtimeclasses`.

## Learn More

Sandboxed runtimes are especially important for multi-tenant clusters and workloads processing untrusted input. They add latency overhead, so evaluate performance requirements. See the Kubernetes RuntimeClass documentation.

**Affected resources:** kv-e2e-storage/Deployment/emptydir-no-limit, kv-e2e-storage/Pod/projected-permissive

</details>

<details>
<summary>Remediation: topology-spread (2 resources affected)</summary>

## Why This Matters

Without topology spread constraints, the scheduler may place all replicas on the same node or in the same availability zone. If that node or zone fails, your entire service goes down despite having multiple replicas. This negates the high-availability benefits of running multiple pods.

## How to Fix

Add topology spread constraints to distribute replicas across failure domains:

```yaml
spec:
  topologySpreadConstraints:
    - maxSkew: 1
      topologyKey: kubernetes.io/hostname
      whenUnsatisfiable: DoNotSchedule
      labelSelector:
        matchLabels:
          app: my-app
    - maxSkew: 1
      topologyKey: topology.kubernetes.io/zone
      whenUnsatisfiable: ScheduleAnyway
```

Use `kubernetes.io/hostname` for node-level spreading and `topology.kubernetes.io/zone` for zone-level spreading.

## Learn More

See the Kubernetes Pod Topology Spread Constraints documentation. Combining hostname and zone constraints provides both node-level and zone-level fault tolerance.

**Affected resources:** kv-e2e-storage/Deployment/emptydir-no-limit, kv-e2e-storage/Pod/projected-permissive

</details>

<details>
<summary>Remediation: limit-range-missing (1 resources affected)</summary>

## Why This Matters

Without a LimitRange, any container can be created without resource constraints. A single runaway or malicious pod can consume all node CPU and memory, causing denial of service for other workloads on the same node.

## How to Fix

Create a LimitRange in the namespace to set default and maximum resource constraints:

```yaml
apiVersion: v1
kind: LimitRange
metadata:
  name: default-limits
  namespace: my-app
spec:
  limits:
    - type: Container
      default:
        cpu: 500m
        memory: 256Mi
      defaultRequest:
        cpu: 100m
        memory: 128Mi
      max:
        cpu: "2"
        memory: 1Gi
```

Containers that omit resource requests/limits will inherit these defaults automatically.

## Learn More

CIS Kubernetes Benchmark 5.2.1 recommends LimitRanges for resource governance. See https://kubernetes.io/docs/concepts/policy/limit-range/ for configuration details.

**Affected resources:** kv-e2e-storage/Namespace/kv-e2e-storage

</details>

<details>
<summary>Remediation: resource-quota-missing (1 resources affected)</summary>

## Why This Matters

Without a ResourceQuota, a single namespace can consume the entire cluster's CPU, memory, and storage. This creates a noisy-neighbor problem where one team's workloads starve others, and makes capacity planning impossible.

## How to Fix

Create a ResourceQuota to cap the namespace's total resource consumption:

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: compute-quota
  namespace: my-app
spec:
  hard:
    requests.cpu: "10"
    requests.memory: 20Gi
    limits.cpu: "20"
    limits.memory: 40Gi
    pods: "50"
    services: "10"
```

Tune quota values based on the namespace's actual workload requirements and cluster capacity.

## Learn More

CIS Kubernetes Benchmark 5.2.2 recommends ResourceQuotas for multi-tenant clusters. See https://kubernetes.io/docs/concepts/policy/resource-quotas/ for quota configuration and enforcement behavior.

**Affected resources:** kv-e2e-storage/Namespace/kv-e2e-storage

</details>

### kv-e2e-workload (769 findings — 🔴8 🟠130 🟡407 🔵223 ⬜1)

| Severity | Check | Resources | Message | Frameworks |
|----------|-------|-----------|---------|-----------|
| 🔴 Critical | host-ipc | kv-e2e-workload/Pod/host-ipc-pod | Pod "host-ipc-pod" has hostIPC enabled, allowing containers to access host shared memory. | CIS 5.2.4 · MITRE T1611 · NSA 1.3 |
| 🔴 Critical | host-network | kv-e2e-workload/Pod/host-network-pod | Pod "host-network-pod" has hostNetwork enabled, bypassing network policies and exposing the host network. | CIS 5.2.5 · MITRE T1611 · MITRE T1040 · NSA 1.3 · NSA 4.1 |
| 🔴 Critical | host-pid | kv-e2e-workload/Pod/host-pid-pod | Pod "host-pid-pod" has hostPID enabled, allowing containers to see all host processes. | CIS 5.2.3 · MITRE T1611 · MITRE T1057 · NSA 1.3 |
| 🔴 Critical | container-runtime-socket | kv-e2e-workload/Pod/hostpath-docker-sock (docker-sock-mount) | Container "docker-sock-mount" mounts container runtime socket "/var/run/docker.sock" via volume "docker-sock". | CIS 5.2.12 · MITRE T1611 · MITRE T1610 · NSA 1.3 |
| 🔴 Critical | host-path-volumes | **3 resources** | Pod "hostpath-docker-sock" mounts hostPath "/var/run/docker.sock" via volume "docker-sock". | CIS 5.2.12 · MITRE T1611 · MITRE T1006 · NSA 1.3 |
| 🔴 Critical | privileged | kv-e2e-workload/Deployment/privileged-container (privileged-app) | Container "privileged-app" is running in privileged mode, granting full host access. | CIS 5.2.2 · MITRE T1611 · NSA 1.1 · NSA 2.1 |
| 🟠 High | automount-token | **26 resources** | Deployment "dangerous-capabilities" auto-mounts a ServiceAccount token. Most workloads do not need Kubernetes API access. | CIS 5.1.6 · MITRE T1552.007 · NSA 3.2 |
| 🟠 High | capabilities-added | **2 resources** | Container "caps-sys-admin" adds dangerous capabilities: SYS_ADMIN, NET_RAW. | CIS 5.2.9 · CIS 5.2.10 · MITRE T1611 · MITRE T1068 · NSA 1.1 · NSA 2.1 |
| 🟠 High | default-service-account | **26 resources** | Deployment "dangerous-capabilities" uses the default ServiceAccount, which may have unintended permissions. | CIS 5.1.5 · CIS 5.1.6 · MITRE T1078.001 · NSA 3.1 · NSA 3.2 |
| 🟠 High | privilege-escalation | **35 resources** | Container "caps-sys-admin" does not set allowPrivilegeEscalation to false, permitting privilege escalation. | CIS 5.2.6 · MITRE T1068 · MITRE T1611 · NSA 1.1 · NSA 2.1 |
| 🟠 High | psa-baseline-violations | **5 resources** | Deployment "dangerous-capabilities" container "caps-sys-admin" violates PSS Baseline: adds dangerous capability "SYS_ADMIN". | CIS 5.2.1 · MITRE T1611 · NSA 2.1 |
| 🟠 High | run-as-root | **31 resources** | Container "caps-sys-admin" does not set runAsNonRoot: true and may run as root. | CIS 5.2.7 · MITRE T1611 · NSA 1.1 |
| 🟠 High | host-ports | kv-e2e-workload/Pod/host-port-pod (host-port-container) | Container "host-port-container" binds to host port 8080, exposing the service directly on the node. | CIS 5.2.13 · MITRE T1611 · NSA 1.3 |
| 🟠 High | host-path-volumes | kv-e2e-workload/Pod/hostpath-var-log | Pod "hostpath-var-log" mounts hostPath "/var/log" via volume "host-logs". | CIS 5.2.12 · MITRE T1611 · MITRE T1006 · NSA 1.3 |
| 🟠 High | network-policy-missing | kv-e2e-workload/Namespace/kv-e2e-workload | Namespace "kv-e2e-workload" has no NetworkPolicy defined. All pods are unrestricted. | CIS 5.3.2 · MITRE T1046 · NSA 4.1 · NSA 4.2 |
| 🟠 High | proc-mount | kv-e2e-workload/Pod/unmasked-proc (unmasked-proc-container) | Container "unmasked-proc-container" has procMount set to Unmasked, exposing sensitive host information via /proc. | CIS 5.6.3 · MITRE T1611 · NSA 1.3 |
| 🟠 High | unsafe-sysctls | kv-e2e-workload/Pod/unsafe-sysctls-shared-pid | Pod configures unsafe sysctls: net.core.somaxconn, kernel.msgmax. | CIS 5.6.3 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | apparmor-profile | **35 resources** | Container "caps-sys-admin" does not have an AppArmor profile set. | CIS 5.6.3 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | capabilities-not-dropped | **35 resources** | Container "caps-sys-admin" does not drop ALL capabilities, leaving it with unnecessary default privileges. | CIS 5.2.8 · CIS 5.2.10 · MITRE T1068 · NSA 1.1 |
| 🟡 Medium | image-pull-policy | **35 resources** | Container "caps-sys-admin" uses a mutable image tag with pullPolicy "IfNotPresent" (image: registry.k8s.io/pause:3.9), risking stale images. | CIS 5.5.1 · MITRE T1525 · NSA 1.4 |
| 🟡 Medium | psa-restricted-violations | **101 resources** | Deployment "dangerous-capabilities" container "caps-sys-admin" violates PSS Restricted: runAsNonRoot is not true. | CIS 5.2.1 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | read-only-rootfs | **35 resources** | Container "caps-sys-admin" does not have a read-only root filesystem. | CIS 5.6.3 · MITRE T1565.001 · NSA 1.2 |
| 🟡 Medium | resource-limits-missing | **33 resources** | Container "caps-sys-admin" is missing both CPU and memory limits. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🟡 Medium | resource-requests-missing | **33 resources** | Container "caps-sys-admin" is missing both CPU and memory requests. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🟡 Medium | run-as-group | **35 resources** | Container "caps-sys-admin" does not set runAsGroup; the process will run as GID 0 (root group) by default. | CIS 5.2.7 · MITRE T1068 · NSA 1.1 |
| 🟡 Medium | seccomp-profile | **34 resources** | Container "caps-sys-admin" does not have a Seccomp profile set at either the container or pod level. | CIS 5.6.2 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | token-projection-config | **6 resources** | Deployment "dangerous-capabilities" does not use explicitly configured projected ServiceAccount tokens with expiry and audience restrictions. | CIS 5.1.6 · MITRE T1552.007 · NSA 3.2 |
| 🟡 Medium | projected-volume-security | **20 resources** | Pod "default-sa-automount" has projected volume "kube-api-access-z5rjm" with defaultMode 0644 which is too permissive. | CIS 5.4.1 · MITRE T1552 · NSA 5.1 |
| 🟡 Medium | host-path-volumes | kv-e2e-workload/Pod/hostpath-opt-data | Pod "hostpath-opt-data" mounts hostPath "/opt/data" via volume "host-data". | CIS 5.2.12 · MITRE T1611 · MITRE T1006 · NSA 1.3 |
| 🟡 Medium | network-policy-egress-unrestricted | kv-e2e-workload/Namespace/kv-e2e-workload | Namespace "kv-e2e-workload" has no NetworkPolicy with egress restrictions. Pods can reach any external destination. | CIS 5.3.2 · MITRE T1048 · NSA 4.2 |
| 🟡 Medium | psa-labels-missing | kv-e2e-workload/Namespace/kv-e2e-workload | Namespace "kv-e2e-workload" is missing the pod-security.kubernetes.io/enforce label; pod security is not enforced. | CIS 5.2.1 · MITRE T1610 · NSA 2.1 |
| 🟡 Medium | selinux-options | kv-e2e-workload/Pod/priv-escalation-selinux (escalation-container) | Container "escalation-container" has dangerous SELinux type "spc_t", which disables SELinux confinement. | CIS 5.6.3 · MITRE T1068 · NSA 2.1 |
| 🟡 Medium | share-process-namespace | kv-e2e-workload/Pod/unsafe-sysctls-shared-pid | Pod "unsafe-sysctls-shared-pid" has shareProcessNamespace enabled, allowing all containers to see each other's processes. | CIS 5.6.3 · MITRE T1057 · NSA 1.3 |
| 🔵 Low | ephemeral-storage-limits | **35 resources** | Container "caps-sys-admin" is missing ephemeral-storage limits. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | image-no-digest | **35 resources** | Container "caps-sys-admin" image is not pinned by digest (image: registry.k8s.io/pause:3.9), allowing tag mutation. | CIS 5.5.1 · MITRE T1525 · NSA 1.4 |
| 🔵 Low | liveness-readiness-probes | **69 resources** | Container "caps-sys-admin" has no liveness probe configured. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | priority-class-missing | **26 resources** | Deployment "dangerous-capabilities" has no PriorityClass set; it will be evicted first during resource pressure. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | runtime-class | **26 resources** | Pod "dangerous-capabilities" does not specify a RuntimeClass, using the default (unsandboxed) runtime. | CIS 5.6.3 · MITRE T1611 · NSA 2.1 |
| 🔵 Low | topology-spread | **26 resources** | Deployment "dangerous-capabilities" has no topology spread constraints; all replicas may be scheduled on the same node. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | limit-range-missing | kv-e2e-workload/Namespace/kv-e2e-workload | Namespace "kv-e2e-workload" has no LimitRange defined. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | resource-quota-missing | kv-e2e-workload/Namespace/kv-e2e-workload | Namespace "kv-e2e-workload" has no ResourceQuota defined. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | lifecycle-hooks | **2 resources** | Container "curl-hook" has a preStop hook with potential network call: "/bin/sh -c curl -s http://monitoring.internal/api/shutdown". | CIS 5.6.3 · MITRE T1059 · NSA 1.3 |
| 🔵 Low | run-as-high-uid | kv-e2e-workload/Pod/low-uid-pod (low-uid-container) | Container "low-uid-container" runs as UID 1000, which is below the recommended minimum of 10000. | CIS 5.2.7 · MITRE T1068 · NSA 1.1 |
| 🔵 Low | resource-limits-ratio | kv-e2e-workload/Deployment/resource-issues (extreme-ratio) | Container "extreme-ratio" has high limits-to-requests ratio for CPU (10.0x) and memory (16.0x), threshold is 3.0x. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| ⬜ Info | startup-probes | kv-e2e-workload/Pod/no-startup-probe (slow-app) | Container "slow-app" has a liveness probe but no startup probe, which can cause restart loops during slow startup. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |

<details>
<summary>host-path-volumes: 3 affected resources</summary>

- `kv-e2e-workload/Pod/hostpath-docker-sock`
- `kv-e2e-workload/Pod/hostpath-etc`
- `kv-e2e-workload/Pod/hostpath-root`

</details>

<details>
<summary>automount-token: 26 affected resources</summary>

- `kv-e2e-workload/Deployment/dangerous-capabilities`
- `kv-e2e-workload/Pod/default-sa-automount`
- `kv-e2e-workload/Pod/explicit-default-sa`
- `kv-e2e-workload/Pod/explicit-root`
- `kv-e2e-workload/Pod/host-ipc-pod`
- `kv-e2e-workload/Pod/host-network-pod`
- `kv-e2e-workload/Pod/host-pid-pod`
- `kv-e2e-workload/Pod/host-port-pod`
- `kv-e2e-workload/Pod/hostpath-docker-sock`
- `kv-e2e-workload/Pod/hostpath-etc`
- `kv-e2e-workload/Pod/hostpath-opt-data`
- `kv-e2e-workload/Pod/hostpath-root`
- `kv-e2e-workload/Pod/hostpath-var-log`
- `kv-e2e-workload/Pod/lifecycle-curl`
- `kv-e2e-workload/Pod/lifecycle-httpget`
- `kv-e2e-workload/Pod/low-uid-pod`
- `kv-e2e-workload/Pod/missing-non-root`
- `kv-e2e-workload/Deployment/missing-profiles`
- `kv-e2e-workload/Pod/no-startup-probe`
- `kv-e2e-workload/Pod/priv-escalation-selinux`
- `kv-e2e-workload/Deployment/privileged-container`
- `kv-e2e-workload/Deployment/pull-policy-issues`
- `kv-e2e-workload/Deployment/resource-issues`
- `kv-e2e-workload/Pod/unmasked-proc`
- `kv-e2e-workload/Pod/unsafe-sysctls-shared-pid`
- `kv-e2e-workload/Deployment/writable-rootfs`

</details>

<details>
<summary>capabilities-added: 2 affected resources</summary>

- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-sys-admin)`
- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-ptrace)`

</details>

<details>
<summary>default-service-account: 26 affected resources</summary>

- `kv-e2e-workload/Deployment/dangerous-capabilities`
- `kv-e2e-workload/Pod/default-sa-automount`
- `kv-e2e-workload/Pod/explicit-default-sa`
- `kv-e2e-workload/Pod/explicit-root`
- `kv-e2e-workload/Pod/host-ipc-pod`
- `kv-e2e-workload/Pod/host-network-pod`
- `kv-e2e-workload/Pod/host-pid-pod`
- `kv-e2e-workload/Pod/host-port-pod`
- `kv-e2e-workload/Pod/hostpath-docker-sock`
- `kv-e2e-workload/Pod/hostpath-etc`
- `kv-e2e-workload/Pod/hostpath-opt-data`
- `kv-e2e-workload/Pod/hostpath-root`
- `kv-e2e-workload/Pod/hostpath-var-log`
- `kv-e2e-workload/Pod/lifecycle-curl`
- `kv-e2e-workload/Pod/lifecycle-httpget`
- `kv-e2e-workload/Pod/low-uid-pod`
- `kv-e2e-workload/Pod/missing-non-root`
- `kv-e2e-workload/Deployment/missing-profiles`
- `kv-e2e-workload/Pod/no-startup-probe`
- `kv-e2e-workload/Pod/priv-escalation-selinux`
- `kv-e2e-workload/Deployment/privileged-container`
- `kv-e2e-workload/Deployment/pull-policy-issues`
- `kv-e2e-workload/Deployment/resource-issues`
- `kv-e2e-workload/Pod/unmasked-proc`
- `kv-e2e-workload/Pod/unsafe-sysctls-shared-pid`
- `kv-e2e-workload/Deployment/writable-rootfs`

</details>

<details>
<summary>privilege-escalation: 35 affected resources</summary>

- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-sys-admin)`
- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-ptrace)`
- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-not-dropped)`
- `kv-e2e-workload/Pod/default-sa-automount (app)`
- `kv-e2e-workload/Pod/explicit-default-sa (app)`
- `kv-e2e-workload/Pod/explicit-root (root-container)`
- `kv-e2e-workload/Pod/host-ipc-pod (ipc-container)`
- `kv-e2e-workload/Pod/host-network-pod (network-container)`
- `kv-e2e-workload/Pod/host-pid-pod (pid-container)`
- `kv-e2e-workload/Pod/host-port-pod (host-port-container)`
- `kv-e2e-workload/Pod/hostpath-docker-sock (docker-sock-mount)`
- `kv-e2e-workload/Pod/hostpath-etc (etc-mount)`
- `kv-e2e-workload/Pod/hostpath-opt-data (data-mount)`
- `kv-e2e-workload/Pod/hostpath-root (root-mount)`
- `kv-e2e-workload/Pod/hostpath-var-log (log-mount)`
- `kv-e2e-workload/Pod/lifecycle-curl (curl-hook)`
- `kv-e2e-workload/Pod/lifecycle-httpget (httpget-hook)`
- `kv-e2e-workload/Pod/low-uid-pod (low-uid-container)`
- `kv-e2e-workload/Pod/missing-non-root (no-security-context)`
- `kv-e2e-workload/Deployment/missing-profiles (no-seccomp-no-apparmor)`
- `kv-e2e-workload/Deployment/missing-profiles (seccomp-only)`
- `kv-e2e-workload/Pod/no-startup-probe (slow-app)`
- `kv-e2e-workload/Pod/priv-escalation-selinux (escalation-container)`
- `kv-e2e-workload/Deployment/privileged-container (privileged-app)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-default)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-explicit)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-never)`
- `kv-e2e-workload/Deployment/resource-issues (no-resources)`
- `kv-e2e-workload/Deployment/resource-issues (limits-no-requests)`
- `kv-e2e-workload/Deployment/resource-issues (extreme-ratio)`
- `kv-e2e-workload/Deployment/resource-issues (requests-no-limits)`
- `kv-e2e-workload/Pod/unmasked-proc (unmasked-proc-container)`
- `kv-e2e-workload/Pod/unsafe-sysctls-shared-pid (sysctls-container)`
- `kv-e2e-workload/Deployment/writable-rootfs (no-readonly)`
- `kv-e2e-workload/Deployment/writable-rootfs (explicit-writable)`

</details>

<details>
<summary>psa-baseline-violations: 5 affected resources</summary>

- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-sys-admin)`
- `kv-e2e-workload/Pod/host-ipc-pod`
- `kv-e2e-workload/Pod/host-network-pod`
- `kv-e2e-workload/Pod/host-pid-pod`
- `kv-e2e-workload/Deployment/privileged-container (privileged-app)`

</details>

<details>
<summary>run-as-root: 31 affected resources</summary>

- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-sys-admin)`
- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-ptrace)`
- `kv-e2e-workload/Pod/default-sa-automount (app)`
- `kv-e2e-workload/Pod/explicit-default-sa (app)`
- `kv-e2e-workload/Pod/explicit-root (root-container)`
- `kv-e2e-workload/Pod/host-ipc-pod (ipc-container)`
- `kv-e2e-workload/Pod/host-network-pod (network-container)`
- `kv-e2e-workload/Pod/host-pid-pod (pid-container)`
- `kv-e2e-workload/Pod/host-port-pod (host-port-container)`
- `kv-e2e-workload/Pod/hostpath-docker-sock (docker-sock-mount)`
- `kv-e2e-workload/Pod/hostpath-etc (etc-mount)`
- `kv-e2e-workload/Pod/hostpath-opt-data (data-mount)`
- `kv-e2e-workload/Pod/hostpath-root (root-mount)`
- `kv-e2e-workload/Pod/hostpath-var-log (log-mount)`
- `kv-e2e-workload/Pod/lifecycle-curl (curl-hook)`
- `kv-e2e-workload/Pod/lifecycle-httpget (httpget-hook)`
- `kv-e2e-workload/Pod/missing-non-root (no-security-context)`
- `kv-e2e-workload/Pod/no-startup-probe (slow-app)`
- `kv-e2e-workload/Pod/priv-escalation-selinux (escalation-container)`
- `kv-e2e-workload/Deployment/privileged-container (privileged-app)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-default)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-explicit)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-never)`
- `kv-e2e-workload/Deployment/resource-issues (no-resources)`
- `kv-e2e-workload/Deployment/resource-issues (limits-no-requests)`
- `kv-e2e-workload/Deployment/resource-issues (extreme-ratio)`
- `kv-e2e-workload/Deployment/resource-issues (requests-no-limits)`
- `kv-e2e-workload/Pod/unmasked-proc (unmasked-proc-container)`
- `kv-e2e-workload/Pod/unsafe-sysctls-shared-pid (sysctls-container)`
- `kv-e2e-workload/Deployment/writable-rootfs (no-readonly)`
- `kv-e2e-workload/Deployment/writable-rootfs (explicit-writable)`

</details>

<details>
<summary>apparmor-profile: 35 affected resources</summary>

- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-sys-admin)`
- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-ptrace)`
- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-not-dropped)`
- `kv-e2e-workload/Pod/default-sa-automount (app)`
- `kv-e2e-workload/Pod/explicit-default-sa (app)`
- `kv-e2e-workload/Pod/explicit-root (root-container)`
- `kv-e2e-workload/Pod/host-ipc-pod (ipc-container)`
- `kv-e2e-workload/Pod/host-network-pod (network-container)`
- `kv-e2e-workload/Pod/host-pid-pod (pid-container)`
- `kv-e2e-workload/Pod/host-port-pod (host-port-container)`
- `kv-e2e-workload/Pod/hostpath-docker-sock (docker-sock-mount)`
- `kv-e2e-workload/Pod/hostpath-etc (etc-mount)`
- `kv-e2e-workload/Pod/hostpath-opt-data (data-mount)`
- `kv-e2e-workload/Pod/hostpath-root (root-mount)`
- `kv-e2e-workload/Pod/hostpath-var-log (log-mount)`
- `kv-e2e-workload/Pod/lifecycle-curl (curl-hook)`
- `kv-e2e-workload/Pod/lifecycle-httpget (httpget-hook)`
- `kv-e2e-workload/Pod/low-uid-pod (low-uid-container)`
- `kv-e2e-workload/Pod/missing-non-root (no-security-context)`
- `kv-e2e-workload/Deployment/missing-profiles (no-seccomp-no-apparmor)`
- `kv-e2e-workload/Deployment/missing-profiles (seccomp-only)`
- `kv-e2e-workload/Pod/no-startup-probe (slow-app)`
- `kv-e2e-workload/Pod/priv-escalation-selinux (escalation-container)`
- `kv-e2e-workload/Deployment/privileged-container (privileged-app)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-default)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-explicit)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-never)`
- `kv-e2e-workload/Deployment/resource-issues (no-resources)`
- `kv-e2e-workload/Deployment/resource-issues (limits-no-requests)`
- `kv-e2e-workload/Deployment/resource-issues (extreme-ratio)`
- `kv-e2e-workload/Deployment/resource-issues (requests-no-limits)`
- `kv-e2e-workload/Pod/unmasked-proc (unmasked-proc-container)`
- `kv-e2e-workload/Pod/unsafe-sysctls-shared-pid (sysctls-container)`
- `kv-e2e-workload/Deployment/writable-rootfs (no-readonly)`
- `kv-e2e-workload/Deployment/writable-rootfs (explicit-writable)`

</details>

<details>
<summary>capabilities-not-dropped: 35 affected resources</summary>

- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-sys-admin)`
- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-ptrace)`
- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-not-dropped)`
- `kv-e2e-workload/Pod/default-sa-automount (app)`
- `kv-e2e-workload/Pod/explicit-default-sa (app)`
- `kv-e2e-workload/Pod/explicit-root (root-container)`
- `kv-e2e-workload/Pod/host-ipc-pod (ipc-container)`
- `kv-e2e-workload/Pod/host-network-pod (network-container)`
- `kv-e2e-workload/Pod/host-pid-pod (pid-container)`
- `kv-e2e-workload/Pod/host-port-pod (host-port-container)`
- `kv-e2e-workload/Pod/hostpath-docker-sock (docker-sock-mount)`
- `kv-e2e-workload/Pod/hostpath-etc (etc-mount)`
- `kv-e2e-workload/Pod/hostpath-opt-data (data-mount)`
- `kv-e2e-workload/Pod/hostpath-root (root-mount)`
- `kv-e2e-workload/Pod/hostpath-var-log (log-mount)`
- `kv-e2e-workload/Pod/lifecycle-curl (curl-hook)`
- `kv-e2e-workload/Pod/lifecycle-httpget (httpget-hook)`
- `kv-e2e-workload/Pod/low-uid-pod (low-uid-container)`
- `kv-e2e-workload/Pod/missing-non-root (no-security-context)`
- `kv-e2e-workload/Deployment/missing-profiles (no-seccomp-no-apparmor)`
- `kv-e2e-workload/Deployment/missing-profiles (seccomp-only)`
- `kv-e2e-workload/Pod/no-startup-probe (slow-app)`
- `kv-e2e-workload/Pod/priv-escalation-selinux (escalation-container)`
- `kv-e2e-workload/Deployment/privileged-container (privileged-app)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-default)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-explicit)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-never)`
- `kv-e2e-workload/Deployment/resource-issues (no-resources)`
- `kv-e2e-workload/Deployment/resource-issues (limits-no-requests)`
- `kv-e2e-workload/Deployment/resource-issues (extreme-ratio)`
- `kv-e2e-workload/Deployment/resource-issues (requests-no-limits)`
- `kv-e2e-workload/Pod/unmasked-proc (unmasked-proc-container)`
- `kv-e2e-workload/Pod/unsafe-sysctls-shared-pid (sysctls-container)`
- `kv-e2e-workload/Deployment/writable-rootfs (no-readonly)`
- `kv-e2e-workload/Deployment/writable-rootfs (explicit-writable)`

</details>

<details>
<summary>image-pull-policy: 35 affected resources</summary>

- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-sys-admin)`
- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-ptrace)`
- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-not-dropped)`
- `kv-e2e-workload/Pod/default-sa-automount (app)`
- `kv-e2e-workload/Pod/explicit-default-sa (app)`
- `kv-e2e-workload/Pod/explicit-root (root-container)`
- `kv-e2e-workload/Pod/host-ipc-pod (ipc-container)`
- `kv-e2e-workload/Pod/host-network-pod (network-container)`
- `kv-e2e-workload/Pod/host-pid-pod (pid-container)`
- `kv-e2e-workload/Pod/host-port-pod (host-port-container)`
- `kv-e2e-workload/Pod/hostpath-docker-sock (docker-sock-mount)`
- `kv-e2e-workload/Pod/hostpath-etc (etc-mount)`
- `kv-e2e-workload/Pod/hostpath-opt-data (data-mount)`
- `kv-e2e-workload/Pod/hostpath-root (root-mount)`
- `kv-e2e-workload/Pod/hostpath-var-log (log-mount)`
- `kv-e2e-workload/Pod/lifecycle-curl (curl-hook)`
- `kv-e2e-workload/Pod/lifecycle-httpget (httpget-hook)`
- `kv-e2e-workload/Pod/low-uid-pod (low-uid-container)`
- `kv-e2e-workload/Pod/missing-non-root (no-security-context)`
- `kv-e2e-workload/Deployment/missing-profiles (no-seccomp-no-apparmor)`
- `kv-e2e-workload/Deployment/missing-profiles (seccomp-only)`
- `kv-e2e-workload/Pod/no-startup-probe (slow-app)`
- `kv-e2e-workload/Pod/priv-escalation-selinux (escalation-container)`
- `kv-e2e-workload/Deployment/privileged-container (privileged-app)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-default)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-explicit)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-never)`
- `kv-e2e-workload/Deployment/resource-issues (no-resources)`
- `kv-e2e-workload/Deployment/resource-issues (limits-no-requests)`
- `kv-e2e-workload/Deployment/resource-issues (extreme-ratio)`
- `kv-e2e-workload/Deployment/resource-issues (requests-no-limits)`
- `kv-e2e-workload/Pod/unmasked-proc (unmasked-proc-container)`
- `kv-e2e-workload/Pod/unsafe-sysctls-shared-pid (sysctls-container)`
- `kv-e2e-workload/Deployment/writable-rootfs (no-readonly)`
- `kv-e2e-workload/Deployment/writable-rootfs (explicit-writable)`

</details>

<details>
<summary>psa-restricted-violations: 101 affected resources</summary>

- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-sys-admin)`
- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-sys-admin)`
- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-sys-admin)`
- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-ptrace)`
- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-ptrace)`
- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-ptrace)`
- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-not-dropped)`
- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-not-dropped)`
- `kv-e2e-workload/Pod/default-sa-automount (app)`
- `kv-e2e-workload/Pod/default-sa-automount (app)`
- `kv-e2e-workload/Pod/default-sa-automount (app)`
- `kv-e2e-workload/Pod/explicit-default-sa (app)`
- `kv-e2e-workload/Pod/explicit-default-sa (app)`
- `kv-e2e-workload/Pod/explicit-default-sa (app)`
- `kv-e2e-workload/Pod/explicit-root (root-container)`
- `kv-e2e-workload/Pod/explicit-root (root-container)`
- `kv-e2e-workload/Pod/explicit-root (root-container)`
- `kv-e2e-workload/Pod/host-ipc-pod (ipc-container)`
- `kv-e2e-workload/Pod/host-ipc-pod (ipc-container)`
- `kv-e2e-workload/Pod/host-ipc-pod (ipc-container)`
- `kv-e2e-workload/Pod/host-network-pod (network-container)`
- `kv-e2e-workload/Pod/host-network-pod (network-container)`
- `kv-e2e-workload/Pod/host-network-pod (network-container)`
- `kv-e2e-workload/Pod/host-pid-pod (pid-container)`
- `kv-e2e-workload/Pod/host-pid-pod (pid-container)`
- `kv-e2e-workload/Pod/host-pid-pod (pid-container)`
- `kv-e2e-workload/Pod/host-port-pod (host-port-container)`
- `kv-e2e-workload/Pod/host-port-pod (host-port-container)`
- `kv-e2e-workload/Pod/host-port-pod (host-port-container)`
- `kv-e2e-workload/Pod/hostpath-docker-sock (docker-sock-mount)`
- `kv-e2e-workload/Pod/hostpath-docker-sock (docker-sock-mount)`
- `kv-e2e-workload/Pod/hostpath-docker-sock (docker-sock-mount)`
- `kv-e2e-workload/Pod/hostpath-etc (etc-mount)`
- `kv-e2e-workload/Pod/hostpath-etc (etc-mount)`
- `kv-e2e-workload/Pod/hostpath-etc (etc-mount)`
- `kv-e2e-workload/Pod/hostpath-opt-data (data-mount)`
- `kv-e2e-workload/Pod/hostpath-opt-data (data-mount)`
- `kv-e2e-workload/Pod/hostpath-opt-data (data-mount)`
- `kv-e2e-workload/Pod/hostpath-root (root-mount)`
- `kv-e2e-workload/Pod/hostpath-root (root-mount)`
- `kv-e2e-workload/Pod/hostpath-root (root-mount)`
- `kv-e2e-workload/Pod/hostpath-var-log (log-mount)`
- `kv-e2e-workload/Pod/hostpath-var-log (log-mount)`
- `kv-e2e-workload/Pod/hostpath-var-log (log-mount)`
- `kv-e2e-workload/Pod/lifecycle-curl (curl-hook)`
- `kv-e2e-workload/Pod/lifecycle-curl (curl-hook)`
- `kv-e2e-workload/Pod/lifecycle-curl (curl-hook)`
- `kv-e2e-workload/Pod/lifecycle-httpget (httpget-hook)`
- `kv-e2e-workload/Pod/lifecycle-httpget (httpget-hook)`
- `kv-e2e-workload/Pod/lifecycle-httpget (httpget-hook)`
- `kv-e2e-workload/Pod/low-uid-pod (low-uid-container)`
- `kv-e2e-workload/Pod/low-uid-pod (low-uid-container)`
- `kv-e2e-workload/Pod/missing-non-root (no-security-context)`
- `kv-e2e-workload/Pod/missing-non-root (no-security-context)`
- `kv-e2e-workload/Pod/missing-non-root (no-security-context)`
- `kv-e2e-workload/Deployment/missing-profiles (no-seccomp-no-apparmor)`
- `kv-e2e-workload/Deployment/missing-profiles (no-seccomp-no-apparmor)`
- `kv-e2e-workload/Deployment/missing-profiles (seccomp-only)`
- `kv-e2e-workload/Deployment/missing-profiles (seccomp-only)`
- `kv-e2e-workload/Pod/no-startup-probe (slow-app)`
- `kv-e2e-workload/Pod/no-startup-probe (slow-app)`
- `kv-e2e-workload/Pod/no-startup-probe (slow-app)`
- `kv-e2e-workload/Pod/priv-escalation-selinux (escalation-container)`
- `kv-e2e-workload/Pod/priv-escalation-selinux (escalation-container)`
- `kv-e2e-workload/Pod/priv-escalation-selinux (escalation-container)`
- `kv-e2e-workload/Deployment/privileged-container (privileged-app)`
- `kv-e2e-workload/Deployment/privileged-container (privileged-app)`
- `kv-e2e-workload/Deployment/privileged-container (privileged-app)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-default)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-default)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-default)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-explicit)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-explicit)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-explicit)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-never)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-never)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-never)`
- `kv-e2e-workload/Deployment/resource-issues (no-resources)`
- `kv-e2e-workload/Deployment/resource-issues (no-resources)`
- `kv-e2e-workload/Deployment/resource-issues (no-resources)`
- `kv-e2e-workload/Deployment/resource-issues (limits-no-requests)`
- `kv-e2e-workload/Deployment/resource-issues (limits-no-requests)`
- `kv-e2e-workload/Deployment/resource-issues (limits-no-requests)`
- `kv-e2e-workload/Deployment/resource-issues (extreme-ratio)`
- `kv-e2e-workload/Deployment/resource-issues (extreme-ratio)`
- `kv-e2e-workload/Deployment/resource-issues (extreme-ratio)`
- `kv-e2e-workload/Deployment/resource-issues (requests-no-limits)`
- `kv-e2e-workload/Deployment/resource-issues (requests-no-limits)`
- `kv-e2e-workload/Deployment/resource-issues (requests-no-limits)`
- `kv-e2e-workload/Pod/unmasked-proc (unmasked-proc-container)`
- `kv-e2e-workload/Pod/unmasked-proc (unmasked-proc-container)`
- `kv-e2e-workload/Pod/unmasked-proc (unmasked-proc-container)`
- `kv-e2e-workload/Pod/unsafe-sysctls-shared-pid (sysctls-container)`
- `kv-e2e-workload/Pod/unsafe-sysctls-shared-pid (sysctls-container)`
- `kv-e2e-workload/Pod/unsafe-sysctls-shared-pid (sysctls-container)`
- `kv-e2e-workload/Deployment/writable-rootfs (no-readonly)`
- `kv-e2e-workload/Deployment/writable-rootfs (no-readonly)`
- `kv-e2e-workload/Deployment/writable-rootfs (no-readonly)`
- `kv-e2e-workload/Deployment/writable-rootfs (explicit-writable)`
- `kv-e2e-workload/Deployment/writable-rootfs (explicit-writable)`
- `kv-e2e-workload/Deployment/writable-rootfs (explicit-writable)`

</details>

<details>
<summary>read-only-rootfs: 35 affected resources</summary>

- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-sys-admin)`
- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-ptrace)`
- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-not-dropped)`
- `kv-e2e-workload/Pod/default-sa-automount (app)`
- `kv-e2e-workload/Pod/explicit-default-sa (app)`
- `kv-e2e-workload/Pod/explicit-root (root-container)`
- `kv-e2e-workload/Pod/host-ipc-pod (ipc-container)`
- `kv-e2e-workload/Pod/host-network-pod (network-container)`
- `kv-e2e-workload/Pod/host-pid-pod (pid-container)`
- `kv-e2e-workload/Pod/host-port-pod (host-port-container)`
- `kv-e2e-workload/Pod/hostpath-docker-sock (docker-sock-mount)`
- `kv-e2e-workload/Pod/hostpath-etc (etc-mount)`
- `kv-e2e-workload/Pod/hostpath-opt-data (data-mount)`
- `kv-e2e-workload/Pod/hostpath-root (root-mount)`
- `kv-e2e-workload/Pod/hostpath-var-log (log-mount)`
- `kv-e2e-workload/Pod/lifecycle-curl (curl-hook)`
- `kv-e2e-workload/Pod/lifecycle-httpget (httpget-hook)`
- `kv-e2e-workload/Pod/low-uid-pod (low-uid-container)`
- `kv-e2e-workload/Pod/missing-non-root (no-security-context)`
- `kv-e2e-workload/Deployment/missing-profiles (no-seccomp-no-apparmor)`
- `kv-e2e-workload/Deployment/missing-profiles (seccomp-only)`
- `kv-e2e-workload/Pod/no-startup-probe (slow-app)`
- `kv-e2e-workload/Pod/priv-escalation-selinux (escalation-container)`
- `kv-e2e-workload/Deployment/privileged-container (privileged-app)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-default)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-explicit)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-never)`
- `kv-e2e-workload/Deployment/resource-issues (no-resources)`
- `kv-e2e-workload/Deployment/resource-issues (limits-no-requests)`
- `kv-e2e-workload/Deployment/resource-issues (extreme-ratio)`
- `kv-e2e-workload/Deployment/resource-issues (requests-no-limits)`
- `kv-e2e-workload/Pod/unmasked-proc (unmasked-proc-container)`
- `kv-e2e-workload/Pod/unsafe-sysctls-shared-pid (sysctls-container)`
- `kv-e2e-workload/Deployment/writable-rootfs (no-readonly)`
- `kv-e2e-workload/Deployment/writable-rootfs (explicit-writable)`

</details>

<details>
<summary>resource-limits-missing: 33 affected resources</summary>

- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-sys-admin)`
- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-ptrace)`
- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-not-dropped)`
- `kv-e2e-workload/Pod/default-sa-automount (app)`
- `kv-e2e-workload/Pod/explicit-default-sa (app)`
- `kv-e2e-workload/Pod/explicit-root (root-container)`
- `kv-e2e-workload/Pod/host-ipc-pod (ipc-container)`
- `kv-e2e-workload/Pod/host-network-pod (network-container)`
- `kv-e2e-workload/Pod/host-pid-pod (pid-container)`
- `kv-e2e-workload/Pod/host-port-pod (host-port-container)`
- `kv-e2e-workload/Pod/hostpath-docker-sock (docker-sock-mount)`
- `kv-e2e-workload/Pod/hostpath-etc (etc-mount)`
- `kv-e2e-workload/Pod/hostpath-opt-data (data-mount)`
- `kv-e2e-workload/Pod/hostpath-root (root-mount)`
- `kv-e2e-workload/Pod/hostpath-var-log (log-mount)`
- `kv-e2e-workload/Pod/lifecycle-curl (curl-hook)`
- `kv-e2e-workload/Pod/lifecycle-httpget (httpget-hook)`
- `kv-e2e-workload/Pod/low-uid-pod (low-uid-container)`
- `kv-e2e-workload/Pod/missing-non-root (no-security-context)`
- `kv-e2e-workload/Deployment/missing-profiles (no-seccomp-no-apparmor)`
- `kv-e2e-workload/Deployment/missing-profiles (seccomp-only)`
- `kv-e2e-workload/Pod/no-startup-probe (slow-app)`
- `kv-e2e-workload/Pod/priv-escalation-selinux (escalation-container)`
- `kv-e2e-workload/Deployment/privileged-container (privileged-app)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-default)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-explicit)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-never)`
- `kv-e2e-workload/Deployment/resource-issues (no-resources)`
- `kv-e2e-workload/Deployment/resource-issues (requests-no-limits)`
- `kv-e2e-workload/Pod/unmasked-proc (unmasked-proc-container)`
- `kv-e2e-workload/Pod/unsafe-sysctls-shared-pid (sysctls-container)`
- `kv-e2e-workload/Deployment/writable-rootfs (no-readonly)`
- `kv-e2e-workload/Deployment/writable-rootfs (explicit-writable)`

</details>

<details>
<summary>resource-requests-missing: 33 affected resources</summary>

- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-sys-admin)`
- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-ptrace)`
- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-not-dropped)`
- `kv-e2e-workload/Pod/default-sa-automount (app)`
- `kv-e2e-workload/Pod/explicit-default-sa (app)`
- `kv-e2e-workload/Pod/explicit-root (root-container)`
- `kv-e2e-workload/Pod/host-ipc-pod (ipc-container)`
- `kv-e2e-workload/Pod/host-network-pod (network-container)`
- `kv-e2e-workload/Pod/host-pid-pod (pid-container)`
- `kv-e2e-workload/Pod/host-port-pod (host-port-container)`
- `kv-e2e-workload/Pod/hostpath-docker-sock (docker-sock-mount)`
- `kv-e2e-workload/Pod/hostpath-etc (etc-mount)`
- `kv-e2e-workload/Pod/hostpath-opt-data (data-mount)`
- `kv-e2e-workload/Pod/hostpath-root (root-mount)`
- `kv-e2e-workload/Pod/hostpath-var-log (log-mount)`
- `kv-e2e-workload/Pod/lifecycle-curl (curl-hook)`
- `kv-e2e-workload/Pod/lifecycle-httpget (httpget-hook)`
- `kv-e2e-workload/Pod/low-uid-pod (low-uid-container)`
- `kv-e2e-workload/Pod/missing-non-root (no-security-context)`
- `kv-e2e-workload/Deployment/missing-profiles (no-seccomp-no-apparmor)`
- `kv-e2e-workload/Deployment/missing-profiles (seccomp-only)`
- `kv-e2e-workload/Pod/no-startup-probe (slow-app)`
- `kv-e2e-workload/Pod/priv-escalation-selinux (escalation-container)`
- `kv-e2e-workload/Deployment/privileged-container (privileged-app)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-default)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-explicit)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-never)`
- `kv-e2e-workload/Deployment/resource-issues (no-resources)`
- `kv-e2e-workload/Deployment/resource-issues (limits-no-requests)`
- `kv-e2e-workload/Pod/unmasked-proc (unmasked-proc-container)`
- `kv-e2e-workload/Pod/unsafe-sysctls-shared-pid (sysctls-container)`
- `kv-e2e-workload/Deployment/writable-rootfs (no-readonly)`
- `kv-e2e-workload/Deployment/writable-rootfs (explicit-writable)`

</details>

<details>
<summary>run-as-group: 35 affected resources</summary>

- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-sys-admin)`
- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-ptrace)`
- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-not-dropped)`
- `kv-e2e-workload/Pod/default-sa-automount (app)`
- `kv-e2e-workload/Pod/explicit-default-sa (app)`
- `kv-e2e-workload/Pod/explicit-root (root-container)`
- `kv-e2e-workload/Pod/host-ipc-pod (ipc-container)`
- `kv-e2e-workload/Pod/host-network-pod (network-container)`
- `kv-e2e-workload/Pod/host-pid-pod (pid-container)`
- `kv-e2e-workload/Pod/host-port-pod (host-port-container)`
- `kv-e2e-workload/Pod/hostpath-docker-sock (docker-sock-mount)`
- `kv-e2e-workload/Pod/hostpath-etc (etc-mount)`
- `kv-e2e-workload/Pod/hostpath-opt-data (data-mount)`
- `kv-e2e-workload/Pod/hostpath-root (root-mount)`
- `kv-e2e-workload/Pod/hostpath-var-log (log-mount)`
- `kv-e2e-workload/Pod/lifecycle-curl (curl-hook)`
- `kv-e2e-workload/Pod/lifecycle-httpget (httpget-hook)`
- `kv-e2e-workload/Pod/low-uid-pod (low-uid-container)`
- `kv-e2e-workload/Pod/missing-non-root (no-security-context)`
- `kv-e2e-workload/Deployment/missing-profiles (no-seccomp-no-apparmor)`
- `kv-e2e-workload/Deployment/missing-profiles (seccomp-only)`
- `kv-e2e-workload/Pod/no-startup-probe (slow-app)`
- `kv-e2e-workload/Pod/priv-escalation-selinux (escalation-container)`
- `kv-e2e-workload/Deployment/privileged-container (privileged-app)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-default)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-explicit)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-never)`
- `kv-e2e-workload/Deployment/resource-issues (no-resources)`
- `kv-e2e-workload/Deployment/resource-issues (limits-no-requests)`
- `kv-e2e-workload/Deployment/resource-issues (extreme-ratio)`
- `kv-e2e-workload/Deployment/resource-issues (requests-no-limits)`
- `kv-e2e-workload/Pod/unmasked-proc (unmasked-proc-container)`
- `kv-e2e-workload/Pod/unsafe-sysctls-shared-pid (sysctls-container)`
- `kv-e2e-workload/Deployment/writable-rootfs (no-readonly)`
- `kv-e2e-workload/Deployment/writable-rootfs (explicit-writable)`

</details>

<details>
<summary>seccomp-profile: 34 affected resources</summary>

- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-sys-admin)`
- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-ptrace)`
- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-not-dropped)`
- `kv-e2e-workload/Pod/default-sa-automount (app)`
- `kv-e2e-workload/Pod/explicit-default-sa (app)`
- `kv-e2e-workload/Pod/explicit-root (root-container)`
- `kv-e2e-workload/Pod/host-ipc-pod (ipc-container)`
- `kv-e2e-workload/Pod/host-network-pod (network-container)`
- `kv-e2e-workload/Pod/host-pid-pod (pid-container)`
- `kv-e2e-workload/Pod/host-port-pod (host-port-container)`
- `kv-e2e-workload/Pod/hostpath-docker-sock (docker-sock-mount)`
- `kv-e2e-workload/Pod/hostpath-etc (etc-mount)`
- `kv-e2e-workload/Pod/hostpath-opt-data (data-mount)`
- `kv-e2e-workload/Pod/hostpath-root (root-mount)`
- `kv-e2e-workload/Pod/hostpath-var-log (log-mount)`
- `kv-e2e-workload/Pod/lifecycle-curl (curl-hook)`
- `kv-e2e-workload/Pod/lifecycle-httpget (httpget-hook)`
- `kv-e2e-workload/Pod/low-uid-pod (low-uid-container)`
- `kv-e2e-workload/Pod/missing-non-root (no-security-context)`
- `kv-e2e-workload/Deployment/missing-profiles (no-seccomp-no-apparmor)`
- `kv-e2e-workload/Pod/no-startup-probe (slow-app)`
- `kv-e2e-workload/Pod/priv-escalation-selinux (escalation-container)`
- `kv-e2e-workload/Deployment/privileged-container (privileged-app)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-default)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-explicit)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-never)`
- `kv-e2e-workload/Deployment/resource-issues (no-resources)`
- `kv-e2e-workload/Deployment/resource-issues (limits-no-requests)`
- `kv-e2e-workload/Deployment/resource-issues (extreme-ratio)`
- `kv-e2e-workload/Deployment/resource-issues (requests-no-limits)`
- `kv-e2e-workload/Pod/unmasked-proc (unmasked-proc-container)`
- `kv-e2e-workload/Pod/unsafe-sysctls-shared-pid (sysctls-container)`
- `kv-e2e-workload/Deployment/writable-rootfs (no-readonly)`
- `kv-e2e-workload/Deployment/writable-rootfs (explicit-writable)`

</details>

<details>
<summary>token-projection-config: 6 affected resources</summary>

- `kv-e2e-workload/Deployment/dangerous-capabilities`
- `kv-e2e-workload/Deployment/missing-profiles`
- `kv-e2e-workload/Deployment/privileged-container`
- `kv-e2e-workload/Deployment/pull-policy-issues`
- `kv-e2e-workload/Deployment/resource-issues`
- `kv-e2e-workload/Deployment/writable-rootfs`

</details>

<details>
<summary>projected-volume-security: 20 affected resources</summary>

- `kv-e2e-workload/Pod/default-sa-automount`
- `kv-e2e-workload/Pod/explicit-default-sa`
- `kv-e2e-workload/Pod/explicit-root`
- `kv-e2e-workload/Pod/host-ipc-pod`
- `kv-e2e-workload/Pod/host-network-pod`
- `kv-e2e-workload/Pod/host-pid-pod`
- `kv-e2e-workload/Pod/host-port-pod`
- `kv-e2e-workload/Pod/hostpath-docker-sock`
- `kv-e2e-workload/Pod/hostpath-etc`
- `kv-e2e-workload/Pod/hostpath-opt-data`
- `kv-e2e-workload/Pod/hostpath-root`
- `kv-e2e-workload/Pod/hostpath-var-log`
- `kv-e2e-workload/Pod/lifecycle-curl`
- `kv-e2e-workload/Pod/lifecycle-httpget`
- `kv-e2e-workload/Pod/low-uid-pod`
- `kv-e2e-workload/Pod/missing-non-root`
- `kv-e2e-workload/Pod/no-startup-probe`
- `kv-e2e-workload/Pod/priv-escalation-selinux`
- `kv-e2e-workload/Pod/unmasked-proc`
- `kv-e2e-workload/Pod/unsafe-sysctls-shared-pid`

</details>

<details>
<summary>ephemeral-storage-limits: 35 affected resources</summary>

- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-sys-admin)`
- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-ptrace)`
- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-not-dropped)`
- `kv-e2e-workload/Pod/default-sa-automount (app)`
- `kv-e2e-workload/Pod/explicit-default-sa (app)`
- `kv-e2e-workload/Pod/explicit-root (root-container)`
- `kv-e2e-workload/Pod/host-ipc-pod (ipc-container)`
- `kv-e2e-workload/Pod/host-network-pod (network-container)`
- `kv-e2e-workload/Pod/host-pid-pod (pid-container)`
- `kv-e2e-workload/Pod/host-port-pod (host-port-container)`
- `kv-e2e-workload/Pod/hostpath-docker-sock (docker-sock-mount)`
- `kv-e2e-workload/Pod/hostpath-etc (etc-mount)`
- `kv-e2e-workload/Pod/hostpath-opt-data (data-mount)`
- `kv-e2e-workload/Pod/hostpath-root (root-mount)`
- `kv-e2e-workload/Pod/hostpath-var-log (log-mount)`
- `kv-e2e-workload/Pod/lifecycle-curl (curl-hook)`
- `kv-e2e-workload/Pod/lifecycle-httpget (httpget-hook)`
- `kv-e2e-workload/Pod/low-uid-pod (low-uid-container)`
- `kv-e2e-workload/Pod/missing-non-root (no-security-context)`
- `kv-e2e-workload/Deployment/missing-profiles (no-seccomp-no-apparmor)`
- `kv-e2e-workload/Deployment/missing-profiles (seccomp-only)`
- `kv-e2e-workload/Pod/no-startup-probe (slow-app)`
- `kv-e2e-workload/Pod/priv-escalation-selinux (escalation-container)`
- `kv-e2e-workload/Deployment/privileged-container (privileged-app)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-default)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-explicit)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-never)`
- `kv-e2e-workload/Deployment/resource-issues (no-resources)`
- `kv-e2e-workload/Deployment/resource-issues (limits-no-requests)`
- `kv-e2e-workload/Deployment/resource-issues (extreme-ratio)`
- `kv-e2e-workload/Deployment/resource-issues (requests-no-limits)`
- `kv-e2e-workload/Pod/unmasked-proc (unmasked-proc-container)`
- `kv-e2e-workload/Pod/unsafe-sysctls-shared-pid (sysctls-container)`
- `kv-e2e-workload/Deployment/writable-rootfs (no-readonly)`
- `kv-e2e-workload/Deployment/writable-rootfs (explicit-writable)`

</details>

<details>
<summary>image-no-digest: 35 affected resources</summary>

- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-sys-admin)`
- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-ptrace)`
- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-not-dropped)`
- `kv-e2e-workload/Pod/default-sa-automount (app)`
- `kv-e2e-workload/Pod/explicit-default-sa (app)`
- `kv-e2e-workload/Pod/explicit-root (root-container)`
- `kv-e2e-workload/Pod/host-ipc-pod (ipc-container)`
- `kv-e2e-workload/Pod/host-network-pod (network-container)`
- `kv-e2e-workload/Pod/host-pid-pod (pid-container)`
- `kv-e2e-workload/Pod/host-port-pod (host-port-container)`
- `kv-e2e-workload/Pod/hostpath-docker-sock (docker-sock-mount)`
- `kv-e2e-workload/Pod/hostpath-etc (etc-mount)`
- `kv-e2e-workload/Pod/hostpath-opt-data (data-mount)`
- `kv-e2e-workload/Pod/hostpath-root (root-mount)`
- `kv-e2e-workload/Pod/hostpath-var-log (log-mount)`
- `kv-e2e-workload/Pod/lifecycle-curl (curl-hook)`
- `kv-e2e-workload/Pod/lifecycle-httpget (httpget-hook)`
- `kv-e2e-workload/Pod/low-uid-pod (low-uid-container)`
- `kv-e2e-workload/Pod/missing-non-root (no-security-context)`
- `kv-e2e-workload/Deployment/missing-profiles (no-seccomp-no-apparmor)`
- `kv-e2e-workload/Deployment/missing-profiles (seccomp-only)`
- `kv-e2e-workload/Pod/no-startup-probe (slow-app)`
- `kv-e2e-workload/Pod/priv-escalation-selinux (escalation-container)`
- `kv-e2e-workload/Deployment/privileged-container (privileged-app)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-default)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-explicit)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-never)`
- `kv-e2e-workload/Deployment/resource-issues (no-resources)`
- `kv-e2e-workload/Deployment/resource-issues (limits-no-requests)`
- `kv-e2e-workload/Deployment/resource-issues (extreme-ratio)`
- `kv-e2e-workload/Deployment/resource-issues (requests-no-limits)`
- `kv-e2e-workload/Pod/unmasked-proc (unmasked-proc-container)`
- `kv-e2e-workload/Pod/unsafe-sysctls-shared-pid (sysctls-container)`
- `kv-e2e-workload/Deployment/writable-rootfs (no-readonly)`
- `kv-e2e-workload/Deployment/writable-rootfs (explicit-writable)`

</details>

<details>
<summary>liveness-readiness-probes: 69 affected resources</summary>

- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-sys-admin)`
- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-sys-admin)`
- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-ptrace)`
- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-ptrace)`
- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-not-dropped)`
- `kv-e2e-workload/Deployment/dangerous-capabilities (caps-not-dropped)`
- `kv-e2e-workload/Pod/default-sa-automount (app)`
- `kv-e2e-workload/Pod/default-sa-automount (app)`
- `kv-e2e-workload/Pod/explicit-default-sa (app)`
- `kv-e2e-workload/Pod/explicit-default-sa (app)`
- `kv-e2e-workload/Pod/explicit-root (root-container)`
- `kv-e2e-workload/Pod/explicit-root (root-container)`
- `kv-e2e-workload/Pod/host-ipc-pod (ipc-container)`
- `kv-e2e-workload/Pod/host-ipc-pod (ipc-container)`
- `kv-e2e-workload/Pod/host-network-pod (network-container)`
- `kv-e2e-workload/Pod/host-network-pod (network-container)`
- `kv-e2e-workload/Pod/host-pid-pod (pid-container)`
- `kv-e2e-workload/Pod/host-pid-pod (pid-container)`
- `kv-e2e-workload/Pod/host-port-pod (host-port-container)`
- `kv-e2e-workload/Pod/host-port-pod (host-port-container)`
- `kv-e2e-workload/Pod/hostpath-docker-sock (docker-sock-mount)`
- `kv-e2e-workload/Pod/hostpath-docker-sock (docker-sock-mount)`
- `kv-e2e-workload/Pod/hostpath-etc (etc-mount)`
- `kv-e2e-workload/Pod/hostpath-etc (etc-mount)`
- `kv-e2e-workload/Pod/hostpath-opt-data (data-mount)`
- `kv-e2e-workload/Pod/hostpath-opt-data (data-mount)`
- `kv-e2e-workload/Pod/hostpath-root (root-mount)`
- `kv-e2e-workload/Pod/hostpath-root (root-mount)`
- `kv-e2e-workload/Pod/hostpath-var-log (log-mount)`
- `kv-e2e-workload/Pod/hostpath-var-log (log-mount)`
- `kv-e2e-workload/Pod/lifecycle-curl (curl-hook)`
- `kv-e2e-workload/Pod/lifecycle-curl (curl-hook)`
- `kv-e2e-workload/Pod/lifecycle-httpget (httpget-hook)`
- `kv-e2e-workload/Pod/lifecycle-httpget (httpget-hook)`
- `kv-e2e-workload/Pod/low-uid-pod (low-uid-container)`
- `kv-e2e-workload/Pod/low-uid-pod (low-uid-container)`
- `kv-e2e-workload/Pod/missing-non-root (no-security-context)`
- `kv-e2e-workload/Pod/missing-non-root (no-security-context)`
- `kv-e2e-workload/Deployment/missing-profiles (no-seccomp-no-apparmor)`
- `kv-e2e-workload/Deployment/missing-profiles (no-seccomp-no-apparmor)`
- `kv-e2e-workload/Deployment/missing-profiles (seccomp-only)`
- `kv-e2e-workload/Deployment/missing-profiles (seccomp-only)`
- `kv-e2e-workload/Pod/no-startup-probe (slow-app)`
- `kv-e2e-workload/Pod/priv-escalation-selinux (escalation-container)`
- `kv-e2e-workload/Pod/priv-escalation-selinux (escalation-container)`
- `kv-e2e-workload/Deployment/privileged-container (privileged-app)`
- `kv-e2e-workload/Deployment/privileged-container (privileged-app)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-default)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-default)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-explicit)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-explicit)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-never)`
- `kv-e2e-workload/Deployment/pull-policy-issues (mutable-tag-never)`
- `kv-e2e-workload/Deployment/resource-issues (no-resources)`
- `kv-e2e-workload/Deployment/resource-issues (no-resources)`
- `kv-e2e-workload/Deployment/resource-issues (limits-no-requests)`
- `kv-e2e-workload/Deployment/resource-issues (limits-no-requests)`
- `kv-e2e-workload/Deployment/resource-issues (extreme-ratio)`
- `kv-e2e-workload/Deployment/resource-issues (extreme-ratio)`
- `kv-e2e-workload/Deployment/resource-issues (requests-no-limits)`
- `kv-e2e-workload/Deployment/resource-issues (requests-no-limits)`
- `kv-e2e-workload/Pod/unmasked-proc (unmasked-proc-container)`
- `kv-e2e-workload/Pod/unmasked-proc (unmasked-proc-container)`
- `kv-e2e-workload/Pod/unsafe-sysctls-shared-pid (sysctls-container)`
- `kv-e2e-workload/Pod/unsafe-sysctls-shared-pid (sysctls-container)`
- `kv-e2e-workload/Deployment/writable-rootfs (no-readonly)`
- `kv-e2e-workload/Deployment/writable-rootfs (no-readonly)`
- `kv-e2e-workload/Deployment/writable-rootfs (explicit-writable)`
- `kv-e2e-workload/Deployment/writable-rootfs (explicit-writable)`

</details>

<details>
<summary>priority-class-missing: 26 affected resources</summary>

- `kv-e2e-workload/Deployment/dangerous-capabilities`
- `kv-e2e-workload/Pod/default-sa-automount`
- `kv-e2e-workload/Pod/explicit-default-sa`
- `kv-e2e-workload/Pod/explicit-root`
- `kv-e2e-workload/Pod/host-ipc-pod`
- `kv-e2e-workload/Pod/host-network-pod`
- `kv-e2e-workload/Pod/host-pid-pod`
- `kv-e2e-workload/Pod/host-port-pod`
- `kv-e2e-workload/Pod/hostpath-docker-sock`
- `kv-e2e-workload/Pod/hostpath-etc`
- `kv-e2e-workload/Pod/hostpath-opt-data`
- `kv-e2e-workload/Pod/hostpath-root`
- `kv-e2e-workload/Pod/hostpath-var-log`
- `kv-e2e-workload/Pod/lifecycle-curl`
- `kv-e2e-workload/Pod/lifecycle-httpget`
- `kv-e2e-workload/Pod/low-uid-pod`
- `kv-e2e-workload/Pod/missing-non-root`
- `kv-e2e-workload/Deployment/missing-profiles`
- `kv-e2e-workload/Pod/no-startup-probe`
- `kv-e2e-workload/Pod/priv-escalation-selinux`
- `kv-e2e-workload/Deployment/privileged-container`
- `kv-e2e-workload/Deployment/pull-policy-issues`
- `kv-e2e-workload/Deployment/resource-issues`
- `kv-e2e-workload/Pod/unmasked-proc`
- `kv-e2e-workload/Pod/unsafe-sysctls-shared-pid`
- `kv-e2e-workload/Deployment/writable-rootfs`

</details>

<details>
<summary>runtime-class: 26 affected resources</summary>

- `kv-e2e-workload/Deployment/dangerous-capabilities`
- `kv-e2e-workload/Pod/default-sa-automount`
- `kv-e2e-workload/Pod/explicit-default-sa`
- `kv-e2e-workload/Pod/explicit-root`
- `kv-e2e-workload/Pod/host-ipc-pod`
- `kv-e2e-workload/Pod/host-network-pod`
- `kv-e2e-workload/Pod/host-pid-pod`
- `kv-e2e-workload/Pod/host-port-pod`
- `kv-e2e-workload/Pod/hostpath-docker-sock`
- `kv-e2e-workload/Pod/hostpath-etc`
- `kv-e2e-workload/Pod/hostpath-opt-data`
- `kv-e2e-workload/Pod/hostpath-root`
- `kv-e2e-workload/Pod/hostpath-var-log`
- `kv-e2e-workload/Pod/lifecycle-curl`
- `kv-e2e-workload/Pod/lifecycle-httpget`
- `kv-e2e-workload/Pod/low-uid-pod`
- `kv-e2e-workload/Pod/missing-non-root`
- `kv-e2e-workload/Deployment/missing-profiles`
- `kv-e2e-workload/Pod/no-startup-probe`
- `kv-e2e-workload/Pod/priv-escalation-selinux`
- `kv-e2e-workload/Deployment/privileged-container`
- `kv-e2e-workload/Deployment/pull-policy-issues`
- `kv-e2e-workload/Deployment/resource-issues`
- `kv-e2e-workload/Pod/unmasked-proc`
- `kv-e2e-workload/Pod/unsafe-sysctls-shared-pid`
- `kv-e2e-workload/Deployment/writable-rootfs`

</details>

<details>
<summary>topology-spread: 26 affected resources</summary>

- `kv-e2e-workload/Deployment/dangerous-capabilities`
- `kv-e2e-workload/Pod/default-sa-automount`
- `kv-e2e-workload/Pod/explicit-default-sa`
- `kv-e2e-workload/Pod/explicit-root`
- `kv-e2e-workload/Pod/host-ipc-pod`
- `kv-e2e-workload/Pod/host-network-pod`
- `kv-e2e-workload/Pod/host-pid-pod`
- `kv-e2e-workload/Pod/host-port-pod`
- `kv-e2e-workload/Pod/hostpath-docker-sock`
- `kv-e2e-workload/Pod/hostpath-etc`
- `kv-e2e-workload/Pod/hostpath-opt-data`
- `kv-e2e-workload/Pod/hostpath-root`
- `kv-e2e-workload/Pod/hostpath-var-log`
- `kv-e2e-workload/Pod/lifecycle-curl`
- `kv-e2e-workload/Pod/lifecycle-httpget`
- `kv-e2e-workload/Pod/low-uid-pod`
- `kv-e2e-workload/Pod/missing-non-root`
- `kv-e2e-workload/Deployment/missing-profiles`
- `kv-e2e-workload/Pod/no-startup-probe`
- `kv-e2e-workload/Pod/priv-escalation-selinux`
- `kv-e2e-workload/Deployment/privileged-container`
- `kv-e2e-workload/Deployment/pull-policy-issues`
- `kv-e2e-workload/Deployment/resource-issues`
- `kv-e2e-workload/Pod/unmasked-proc`
- `kv-e2e-workload/Pod/unsafe-sysctls-shared-pid`
- `kv-e2e-workload/Deployment/writable-rootfs`

</details>

<details>
<summary>lifecycle-hooks: 2 affected resources</summary>

- `kv-e2e-workload/Pod/lifecycle-curl (curl-hook)`
- `kv-e2e-workload/Pod/lifecycle-httpget (httpget-hook)`

</details>

<details>
<summary>Remediation: host-ipc (1 resources affected)</summary>

## Why This Matters

When hostIPC is enabled, containers can access the host's shared memory segments, semaphores, and message queues. An attacker can exploit this to read sensitive data from other processes, inject malicious code into shared memory segments used by host services, or interfere with inter-process communication between system daemons.

## How to Fix

Disable host IPC namespace sharing in the pod spec:

```yaml
spec:
  hostIPC: false
```

If your application uses shared memory for inter-container communication, use emptyDir volumes with `medium: Memory` instead, which provides a pod-scoped tmpfs without exposing the host IPC namespace.

## Learn More

This check aligns with CIS Benchmark 5.2.3 and the Pod Security Standards "Baseline" profile. IPC namespace isolation prevents cross-process data leakage between containers and the host.

**Affected resources:** kv-e2e-workload/Pod/host-ipc-pod

</details>

<details>
<summary>Remediation: host-network (1 resources affected)</summary>

## Why This Matters

Containers with hostNetwork bypass Kubernetes NetworkPolicies entirely and gain access to all network interfaces on the node, including the node's IP address and loopback. An attacker can use this to sniff traffic from other pods, access node-local services such as the kubelet API on port 10250, or impersonate the node on the network.

## How to Fix

Disable host networking in the pod spec and use Kubernetes Services for exposure:

```yaml
spec:
  hostNetwork: false
```

Use ClusterIP Services, NodePort, LoadBalancer, or Ingress resources to expose your application. Only CNI plugins, kube-proxy, and certain monitoring agents legitimately need host networking.

## Learn More

This aligns with CIS Benchmark 5.2.4 and the Pod Security Standards "Baseline" profile. Network namespace isolation is essential for NetworkPolicy enforcement and cluster network segmentation.

**Affected resources:** kv-e2e-workload/Pod/host-network-pod

</details>

<details>
<summary>Remediation: host-pid (1 resources affected)</summary>

## Why This Matters

When hostPID is enabled, containers share the host's process ID namespace and can see every process running on the node, including processes from other pods and system daemons. An attacker can use this to inspect environment variables containing secrets, send signals to critical processes, or exploit /proc entries to escape the container entirely.

## How to Fix

Disable host PID namespace sharing in the pod spec:

```yaml
spec:
  hostPID: false
```

If you need process visibility for monitoring or debugging, consider using ephemeral containers or a dedicated monitoring DaemonSet with tightly scoped RBAC instead.

## Learn More

This check aligns with CIS Benchmark 5.2.2 and the Pod Security Standards "Baseline" profile, which prohibits hostPID. Process namespace isolation is a fundamental container security boundary.

**Affected resources:** kv-e2e-workload/Pod/host-pid-pod

</details>

<details>
<summary>Remediation: container-runtime-socket (1 resources affected)</summary>

## Why This Matters

Mounting the container runtime socket (docker.sock, containerd.sock, crio.sock) gives the container full control over every container on the node. An attacker can create privileged containers, access secrets from other pods, or escape to the host entirely. This is one of the most critical container escape vectors.

## How to Fix

Remove the hostPath volume that mounts the runtime socket:

```yaml
spec:
  volumes:
    # Remove this volume entirely:
    # - name: docker-sock
    #   hostPath:
    #     path: /var/run/docker.sock
  containers:
    - name: app
      volumeMounts: []            # Remove the corresponding mount
```

If you need to build container images, use rootless builders like Kaniko or Buildah instead of Docker-in-Docker.

## Learn More

See MITRE ATT&CK T1611 (Escape to Host) for container escape techniques. The CIS Kubernetes Benchmark and NSA/CISA Hardening Guide both prohibit mounting container runtime sockets.

**Affected resources:** kv-e2e-workload/Pod/hostpath-docker-sock

</details>

<details>
<summary>Remediation: host-path-volumes (5 resources affected)</summary>

## Why This Matters

hostPath volumes give containers direct, unrestricted access to the host node's filesystem. Depending on the path mounted, an attacker can read sensitive host files (/etc/shadow), access container runtime sockets for escape, or modify system binaries. This is one of the most common paths to full node compromise.

## How to Fix

Replace hostPath volumes with safer alternatives:

```yaml
volumes:
  - name: data
    emptyDir: {}          # Pod-scoped temporary storage
  - name: persistent
    persistentVolumeClaim:
      claimName: my-pvc  # Managed storage
```

If host filesystem access is absolutely required (e.g., for log collectors or node monitoring), mount the most restrictive path possible and set `readOnly: true` in the volumeMount.

## Learn More

hostPath volumes are prohibited in the Pod Security Standards "Baseline" profile. Refer to CIS Benchmark 5.2.13 and use PersistentVolumeClaims with CSI drivers for production data storage needs.

**Affected resources:** kv-e2e-workload/Pod/hostpath-docker-sock, kv-e2e-workload/Pod/hostpath-etc, kv-e2e-workload/Pod/hostpath-root, kv-e2e-workload/Pod/hostpath-var-log, kv-e2e-workload/Pod/hostpath-opt-data

</details>

<details>
<summary>Remediation: privileged (1 resources affected)</summary>

## Why This Matters

A privileged container runs with all Linux capabilities and has direct access to the host's devices, filesystems, and kernel. An attacker who compromises a privileged container can immediately escape to the host node, access secrets from other pods, and pivot across the entire cluster. This is the single most dangerous workload misconfiguration.

## How to Fix

Set `privileged` to `false` in the container's securityContext:

```yaml
securityContext:
  privileged: false
  allowPrivilegeEscalation: false
  capabilities:
    drop: ["ALL"]
```

If your container requires specific host access (e.g., network configuration), grant only the individual capabilities it needs via `capabilities.add` instead of enabling full privileged mode.

## Learn More

This check aligns with CIS Kubernetes Benchmark 5.2.1 and the Pod Security Standards "Baseline" profile, which both prohibit privileged containers. See the Kubernetes documentation on Pod Security Standards for details.

**Affected resources:** kv-e2e-workload/Deployment/privileged-container

</details>

<details>
<summary>Remediation: automount-token (26 resources affected)</summary>

## Why This Matters

When a ServiceAccount token is auto-mounted, every container in the pod can call the Kubernetes API. If a container is compromised through a vulnerability or misconfiguration, the attacker gains API access to enumerate resources, read secrets, or escalate privileges.

## How to Fix

Disable auto-mounting at the pod spec level for workloads that do not need API access:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      automountServiceAccountToken: false
      containers:
        - name: app
          image: my-app:latest
```

For workloads that do require API access, use projected tokens with bounded lifetime and audience restrictions instead of the default long-lived token.

## Learn More

Refer to the Kubernetes documentation on configuring service accounts for pods and CIS Kubernetes Benchmark 5.1.6 for auto-mount token guidance.

**Affected resources:** kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Pod/default-sa-automount, kv-e2e-workload/Pod/explicit-default-sa, kv-e2e-workload/Pod/explicit-root, kv-e2e-workload/Pod/host-ipc-pod, kv-e2e-workload/Pod/host-network-pod, kv-e2e-workload/Pod/host-pid-pod, kv-e2e-workload/Pod/host-port-pod, kv-e2e-workload/Pod/hostpath-docker-sock, kv-e2e-workload/Pod/hostpath-etc, kv-e2e-workload/Pod/hostpath-opt-data, kv-e2e-workload/Pod/hostpath-root, kv-e2e-workload/Pod/hostpath-var-log, kv-e2e-workload/Pod/lifecycle-curl, kv-e2e-workload/Pod/lifecycle-httpget, kv-e2e-workload/Pod/low-uid-pod, kv-e2e-workload/Pod/missing-non-root, kv-e2e-workload/Deployment/missing-profiles, kv-e2e-workload/Pod/no-startup-probe, kv-e2e-workload/Pod/priv-escalation-selinux, kv-e2e-workload/Deployment/privileged-container, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Pod/unmasked-proc, kv-e2e-workload/Pod/unsafe-sysctls-shared-pid, kv-e2e-workload/Deployment/writable-rootfs

</details>

<details>
<summary>Remediation: capabilities-added (2 resources affected)</summary>

## Why This Matters

Linux capabilities like SYS_ADMIN, NET_RAW, and SYS_PTRACE grant kernel-level powers that dramatically expand a container's attack surface. SYS_ADMIN alone enables filesystem mounts and namespace manipulation that can lead to container escape. NET_RAW allows ARP spoofing and network sniffing attacks within the cluster.

## How to Fix

Drop all capabilities and only add back the specific ones your application truly requires:

```yaml
securityContext:
  capabilities:
    drop: ["ALL"]
    add: []  # Only add specific caps after careful review
```

If your application needs to bind to ports below 1024, consider using a Kubernetes Service instead of granting NET_BIND_SERVICE. If setup tasks need elevated permissions, use an init container.

## Learn More

The Pod Security Standards "Restricted" profile only allows NET_BIND_SERVICE. Refer to the Linux capabilities man page (capabilities(7)) and CIS Benchmark 5.2.7-5.2.9 for guidance on acceptable capabilities.

**Affected resources:** kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Deployment/dangerous-capabilities

</details>

<details>
<summary>Remediation: default-service-account (26 resources affected)</summary>

## Why This Matters

The default ServiceAccount is shared by every pod in a namespace. If any pod is compromised, the attacker inherits whatever permissions have been granted to the default account via role bindings, enabling lateral movement across all workloads sharing it.

## How to Fix

Create a dedicated ServiceAccount for each workload and reference it in the pod spec:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-app
  namespace: production
automountServiceAccountToken: false
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      serviceAccountName: my-app
```

Grant only the permissions the workload actually needs via a dedicated Role and RoleBinding.

## Learn More

See the Kubernetes documentation on managing service accounts and CIS Kubernetes Benchmark 5.1.5 for guidance on ensuring default service accounts are not actively used.

**Affected resources:** kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Pod/default-sa-automount, kv-e2e-workload/Pod/explicit-default-sa, kv-e2e-workload/Pod/explicit-root, kv-e2e-workload/Pod/host-ipc-pod, kv-e2e-workload/Pod/host-network-pod, kv-e2e-workload/Pod/host-pid-pod, kv-e2e-workload/Pod/host-port-pod, kv-e2e-workload/Pod/hostpath-docker-sock, kv-e2e-workload/Pod/hostpath-etc, kv-e2e-workload/Pod/hostpath-opt-data, kv-e2e-workload/Pod/hostpath-root, kv-e2e-workload/Pod/hostpath-var-log, kv-e2e-workload/Pod/lifecycle-curl, kv-e2e-workload/Pod/lifecycle-httpget, kv-e2e-workload/Pod/low-uid-pod, kv-e2e-workload/Pod/missing-non-root, kv-e2e-workload/Deployment/missing-profiles, kv-e2e-workload/Pod/no-startup-probe, kv-e2e-workload/Pod/priv-escalation-selinux, kv-e2e-workload/Deployment/privileged-container, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Pod/unmasked-proc, kv-e2e-workload/Pod/unsafe-sysctls-shared-pid, kv-e2e-workload/Deployment/writable-rootfs

</details>

<details>
<summary>Remediation: privilege-escalation (35 resources affected)</summary>

## Why This Matters

By default, Kubernetes allows containers to escalate privileges via setuid/setgid binaries, which let a process gain more permissions than its parent. An attacker can exploit this using setuid binaries already present in the container image (like `su`, `sudo`, or `ping`) to elevate from a low-privilege user to root.

## How to Fix

Explicitly disable privilege escalation in the container's securityContext:

```yaml
securityContext:
  allowPrivilegeEscalation: false
  runAsNonRoot: true
  capabilities:
    drop: ["ALL"]
```

This blocks the use of setuid/setgid binaries and prevents the no_new_privs Linux flag from being cleared. The vast majority of application containers do not need privilege escalation.

## Learn More

This is required by the Pod Security Standards "Restricted" profile and CIS Benchmark 5.2.5. Disabling privilege escalation is one of the most impactful single-line security improvements you can make.

**Affected resources:** kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Pod/default-sa-automount, kv-e2e-workload/Pod/explicit-default-sa, kv-e2e-workload/Pod/explicit-root, kv-e2e-workload/Pod/host-ipc-pod, kv-e2e-workload/Pod/host-network-pod, kv-e2e-workload/Pod/host-pid-pod, kv-e2e-workload/Pod/host-port-pod, kv-e2e-workload/Pod/hostpath-docker-sock, kv-e2e-workload/Pod/hostpath-etc, kv-e2e-workload/Pod/hostpath-opt-data, kv-e2e-workload/Pod/hostpath-root, kv-e2e-workload/Pod/hostpath-var-log, kv-e2e-workload/Pod/lifecycle-curl, kv-e2e-workload/Pod/lifecycle-httpget, kv-e2e-workload/Pod/low-uid-pod, kv-e2e-workload/Pod/missing-non-root, kv-e2e-workload/Deployment/missing-profiles, kv-e2e-workload/Deployment/missing-profiles, kv-e2e-workload/Pod/no-startup-probe, kv-e2e-workload/Pod/priv-escalation-selinux, kv-e2e-workload/Deployment/privileged-container, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Pod/unmasked-proc, kv-e2e-workload/Pod/unsafe-sysctls-shared-pid, kv-e2e-workload/Deployment/writable-rootfs, kv-e2e-workload/Deployment/writable-rootfs

</details>

<details>
<summary>Remediation: psa-baseline-violations (5 resources affected)</summary>

## Why This Matters

Adding ALL or SYS_ADMIN capabilities grants the container near-root privileges on the host. SYS_ADMIN alone enables mounting filesystems, loading kernel modules, and other operations that can lead to full container escape.

## How to Fix

Drop all capabilities and add back only the specific ones your application requires:

```yaml
securityContext:
  capabilities:
    drop: [ALL]
    add: [NET_BIND_SERVICE]  # Only what is truly needed
```

Test your application with all capabilities dropped first, then add back only those that cause failures.

## Learn More

See the Pod Security Standards Baseline profile and the capabilities(7) man page for the full list of Linux capabilities. CIS Kubernetes Benchmark 5.2.7 recommends minimizing the set of added capabilities.

**Affected resources:** kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Pod/host-ipc-pod, kv-e2e-workload/Pod/host-network-pod, kv-e2e-workload/Pod/host-pid-pod, kv-e2e-workload/Deployment/privileged-container

</details>

<details>
<summary>Remediation: run-as-root (31 resources affected)</summary>

## Why This Matters

Without `runAsNonRoot: true`, Kubernetes does not enforce non-root execution and the container may default to running as UID 0 depending on the image's USER directive. If the image defaults to root, the container process gains full privileges, increasing the blast radius of any compromise or container escape.

## How to Fix

Enforce non-root execution in the securityContext:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
```

With `runAsNonRoot: true`, Kubernetes will reject the pod at admission time if the container image attempts to run as root. Setting an explicit `runAsUser` provides an additional guarantee.

## Learn More

This aligns with CIS Benchmark 5.2.6 and the Pod Security Standards "Restricted" profile. The `runAsNonRoot` field acts as a safety net even when images change their default USER.

**Affected resources:** kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Pod/default-sa-automount, kv-e2e-workload/Pod/explicit-default-sa, kv-e2e-workload/Pod/explicit-root, kv-e2e-workload/Pod/host-ipc-pod, kv-e2e-workload/Pod/host-network-pod, kv-e2e-workload/Pod/host-pid-pod, kv-e2e-workload/Pod/host-port-pod, kv-e2e-workload/Pod/hostpath-docker-sock, kv-e2e-workload/Pod/hostpath-etc, kv-e2e-workload/Pod/hostpath-opt-data, kv-e2e-workload/Pod/hostpath-root, kv-e2e-workload/Pod/hostpath-var-log, kv-e2e-workload/Pod/lifecycle-curl, kv-e2e-workload/Pod/lifecycle-httpget, kv-e2e-workload/Pod/missing-non-root, kv-e2e-workload/Pod/no-startup-probe, kv-e2e-workload/Pod/priv-escalation-selinux, kv-e2e-workload/Deployment/privileged-container, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Pod/unmasked-proc, kv-e2e-workload/Pod/unsafe-sysctls-shared-pid, kv-e2e-workload/Deployment/writable-rootfs, kv-e2e-workload/Deployment/writable-rootfs

</details>

<details>
<summary>Remediation: host-ports (1 resources affected)</summary>

## Why This Matters

Binding to a host port exposes your service directly on the node's network interface, bypassing Kubernetes Service abstractions and NetworkPolicies. It also ties each pod replica to a unique node (since two pods cannot share the same host port), severely limiting scheduling flexibility, rolling updates, and scaling.

## How to Fix

Remove the hostPort and use Kubernetes Services to expose your application:

```yaml
ports:
  - containerPort: 8080
    protocol: TCP
    # Remove hostPort entirely
```

Use a ClusterIP Service for internal traffic, NodePort or LoadBalancer for external access, or an Ingress controller for HTTP routing.

## Learn More

Host ports are prohibited by the Pod Security Standards "Baseline" profile. The only common legitimate use is for DaemonSets that must bind to a well-known port on every node (e.g., log collectors).

**Affected resources:** kv-e2e-workload/Pod/host-port-pod

</details>

<details>
<summary>Remediation: network-policy-missing (1 resources affected)</summary>

## Why This Matters

Without NetworkPolicies, every pod in this namespace can communicate freely with every other pod in the cluster. If an attacker compromises a single pod, they can move laterally to databases, internal APIs, and other sensitive services with no network-level barriers.

## How to Fix

Create a default-deny NetworkPolicy for the namespace, then add targeted allow rules for legitimate traffic:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: my-namespace
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
```

After applying the default-deny, create additional NetworkPolicy resources that whitelist only the specific ingress and egress flows your workloads require.

## Learn More

See the Kubernetes documentation on NetworkPolicies and CIS Kubernetes Benchmark 5.3.2. A CNI plugin that supports NetworkPolicy (Calico, Cilium, Weave Net) must be installed for policies to take effect.

**Affected resources:** kv-e2e-workload/Namespace/kv-e2e-workload

</details>

<details>
<summary>Remediation: proc-mount (1 resources affected)</summary>

## Why This Matters

Kubernetes masks certain paths in /proc by default to prevent containers from reading sensitive kernel information such as hardware details, other process data, and kernel parameters. An unmasked /proc filesystem exposes these paths and can be used as a stepping stone for container escape attacks by manipulating cgroup files or accessing kernel interfaces.

## How to Fix

Use the default masked proc mount or remove the procMount field entirely:

```yaml
securityContext:
  procMount: Default
```

The Default value masks sensitive paths like /proc/kcore, /proc/keys, and /proc/timer_list. If you need raw /proc access for debugging, use ephemeral containers in non-production environments only.

## Learn More

Unmasked procMount is prohibited by the Pod Security Standards "Baseline" profile. The masked paths in /proc prevent information disclosure that could aid in kernel exploitation or container escape.

**Affected resources:** kv-e2e-workload/Pod/unmasked-proc

</details>

<details>
<summary>Remediation: unsafe-sysctls (1 resources affected)</summary>

## Why This Matters

Unsafe sysctls modify kernel parameters that are not namespaced, meaning they can affect the host system and all other pods running on the same node. An attacker with the ability to set unsafe sysctls can degrade node stability, interfere with network traffic, or weaken security settings for the entire node.

## How to Fix

Remove unsafe sysctls and use only the kubelet-allowlisted safe set:

```yaml
spec:
  securityContext:
    sysctls:
      - name: net.ipv4.ip_local_port_range
        value: "1024 65535"
```

Safe sysctls include: `kernel.shm_rmid_forced`, `net.ipv4.ip_local_port_range`, `net.ipv4.tcp_syncookies`, `net.ipv4.ping_group_range`, `net.ipv4.ip_unprivileged_port_start`, and `net.ipv4.ip_local_reserved_ports`.

## Learn More

The kubelet must be explicitly configured to allow unsafe sysctls via --allowed-unsafe-sysctls. Refer to the Kubernetes sysctl documentation and CIS Benchmark 5.2.11 for detailed guidance.

**Affected resources:** kv-e2e-workload/Pod/unsafe-sysctls-shared-pid

</details>

<details>
<summary>Remediation: apparmor-profile (35 resources affected)</summary>

## Why This Matters

AppArmor provides mandatory access control (MAC) that restricts which files, network resources, and capabilities a container process can access. Without an AppArmor profile, the container operates without these restrictions, allowing an attacker with code execution to access any file the container user can read and make unrestricted network connections.

## How to Fix

Apply an AppArmor profile in the container's securityContext (Kubernetes 1.30+):

```yaml
securityContext:
  appArmorProfile:
    type: RuntimeDefault
```

The RuntimeDefault profile provides sensible restrictions for most applications. For tighter control, create a custom Localhost profile that only allows the specific file and network access your application needs.

## Learn More

AppArmor is available on Debian/Ubuntu-based nodes. RHEL/CentOS nodes use SELinux instead. Both provide MAC enforcement. Refer to CIS Benchmark 5.7.5 and the Kubernetes AppArmor documentation.

**Affected resources:** kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Pod/default-sa-automount, kv-e2e-workload/Pod/explicit-default-sa, kv-e2e-workload/Pod/explicit-root, kv-e2e-workload/Pod/host-ipc-pod, kv-e2e-workload/Pod/host-network-pod, kv-e2e-workload/Pod/host-pid-pod, kv-e2e-workload/Pod/host-port-pod, kv-e2e-workload/Pod/hostpath-docker-sock, kv-e2e-workload/Pod/hostpath-etc, kv-e2e-workload/Pod/hostpath-opt-data, kv-e2e-workload/Pod/hostpath-root, kv-e2e-workload/Pod/hostpath-var-log, kv-e2e-workload/Pod/lifecycle-curl, kv-e2e-workload/Pod/lifecycle-httpget, kv-e2e-workload/Pod/low-uid-pod, kv-e2e-workload/Pod/missing-non-root, kv-e2e-workload/Deployment/missing-profiles, kv-e2e-workload/Deployment/missing-profiles, kv-e2e-workload/Pod/no-startup-probe, kv-e2e-workload/Pod/priv-escalation-selinux, kv-e2e-workload/Deployment/privileged-container, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Pod/unmasked-proc, kv-e2e-workload/Pod/unsafe-sysctls-shared-pid, kv-e2e-workload/Deployment/writable-rootfs, kv-e2e-workload/Deployment/writable-rootfs

</details>

<details>
<summary>Remediation: capabilities-not-dropped (35 resources affected)</summary>

## Why This Matters

By default, containers receive a set of Linux capabilities including KILL, SETUID, SETGID, and NET_RAW. These defaults are rarely needed by application code and significantly increase the potential damage from a container compromise. Dropping all capabilities follows the principle of least privilege.

## How to Fix

Explicitly drop all capabilities and selectively add back only what your application needs:

```yaml
securityContext:
  capabilities:
    drop: ["ALL"]
    add: ["NET_BIND_SERVICE"]  # Only if needed
```

Most web applications, API servers, and background workers run perfectly with all capabilities dropped. Test your application after making this change to confirm no functionality is lost.

## Learn More

This is required by the Pod Security Standards "Restricted" profile and aligns with CIS Benchmark 5.2.7. Kubernetes best practice is to treat capability grants as exceptions that require explicit justification.

**Affected resources:** kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Pod/default-sa-automount, kv-e2e-workload/Pod/explicit-default-sa, kv-e2e-workload/Pod/explicit-root, kv-e2e-workload/Pod/host-ipc-pod, kv-e2e-workload/Pod/host-network-pod, kv-e2e-workload/Pod/host-pid-pod, kv-e2e-workload/Pod/host-port-pod, kv-e2e-workload/Pod/hostpath-docker-sock, kv-e2e-workload/Pod/hostpath-etc, kv-e2e-workload/Pod/hostpath-opt-data, kv-e2e-workload/Pod/hostpath-root, kv-e2e-workload/Pod/hostpath-var-log, kv-e2e-workload/Pod/lifecycle-curl, kv-e2e-workload/Pod/lifecycle-httpget, kv-e2e-workload/Pod/low-uid-pod, kv-e2e-workload/Pod/missing-non-root, kv-e2e-workload/Deployment/missing-profiles, kv-e2e-workload/Deployment/missing-profiles, kv-e2e-workload/Pod/no-startup-probe, kv-e2e-workload/Pod/priv-escalation-selinux, kv-e2e-workload/Deployment/privileged-container, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Pod/unmasked-proc, kv-e2e-workload/Pod/unsafe-sysctls-shared-pid, kv-e2e-workload/Deployment/writable-rootfs, kv-e2e-workload/Deployment/writable-rootfs

</details>

<details>
<summary>Remediation: image-pull-policy (35 resources affected)</summary>

## Why This Matters

When a mutable image tag is used without `imagePullPolicy: Always`, Kubernetes may serve a cached version of the image from the node. If the tag has been updated in the registry (with a security patch or -- worse -- a compromised layer), the running container will not reflect those changes.

## How to Fix

Set `imagePullPolicy: Always` for any container using a mutable tag:

```yaml
containers:
  - name: app
    image: nginx:1.25.3
    imagePullPolicy: Always   # Forces fresh pull each time
```

Alternatively, pin images by digest (`image@sha256:...`), which makes the pull policy irrelevant because the content is immutable.

## Learn More

See the Kubernetes documentation on image pull policies and CIS Kubernetes Benchmark 5.4.2 for pull policy guidance.

**Affected resources:** kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Pod/default-sa-automount, kv-e2e-workload/Pod/explicit-default-sa, kv-e2e-workload/Pod/explicit-root, kv-e2e-workload/Pod/host-ipc-pod, kv-e2e-workload/Pod/host-network-pod, kv-e2e-workload/Pod/host-pid-pod, kv-e2e-workload/Pod/host-port-pod, kv-e2e-workload/Pod/hostpath-docker-sock, kv-e2e-workload/Pod/hostpath-etc, kv-e2e-workload/Pod/hostpath-opt-data, kv-e2e-workload/Pod/hostpath-root, kv-e2e-workload/Pod/hostpath-var-log, kv-e2e-workload/Pod/lifecycle-curl, kv-e2e-workload/Pod/lifecycle-httpget, kv-e2e-workload/Pod/low-uid-pod, kv-e2e-workload/Pod/missing-non-root, kv-e2e-workload/Deployment/missing-profiles, kv-e2e-workload/Deployment/missing-profiles, kv-e2e-workload/Pod/no-startup-probe, kv-e2e-workload/Pod/priv-escalation-selinux, kv-e2e-workload/Deployment/privileged-container, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Pod/unmasked-proc, kv-e2e-workload/Pod/unsafe-sysctls-shared-pid, kv-e2e-workload/Deployment/writable-rootfs, kv-e2e-workload/Deployment/writable-rootfs

</details>

<details>
<summary>Remediation: psa-restricted-violations (101 resources affected)</summary>

## Why This Matters

Running as root inside a container means that any container escape vulnerability immediately grants root access on the host node. Even without an escape, root inside the container can modify sensitive files, install packages, and access capabilities that non-root users cannot.

## How to Fix

Set `runAsNonRoot: true` and specify a non-root user ID in the security context:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
```

Set this at the pod level to apply to all containers. Ensure your container image supports running as a non-root user (many official images do).

## Learn More

See the Pod Security Standards Restricted profile and CIS Kubernetes Benchmark 5.2.6. Running as non-root is a fundamental container security best practice.

**Affected resources:** kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Pod/default-sa-automount, kv-e2e-workload/Pod/default-sa-automount, kv-e2e-workload/Pod/default-sa-automount, kv-e2e-workload/Pod/explicit-default-sa, kv-e2e-workload/Pod/explicit-default-sa, kv-e2e-workload/Pod/explicit-default-sa, kv-e2e-workload/Pod/explicit-root, kv-e2e-workload/Pod/explicit-root, kv-e2e-workload/Pod/explicit-root, kv-e2e-workload/Pod/host-ipc-pod, kv-e2e-workload/Pod/host-ipc-pod, kv-e2e-workload/Pod/host-ipc-pod, kv-e2e-workload/Pod/host-network-pod, kv-e2e-workload/Pod/host-network-pod, kv-e2e-workload/Pod/host-network-pod, kv-e2e-workload/Pod/host-pid-pod, kv-e2e-workload/Pod/host-pid-pod, kv-e2e-workload/Pod/host-pid-pod, kv-e2e-workload/Pod/host-port-pod, kv-e2e-workload/Pod/host-port-pod, kv-e2e-workload/Pod/host-port-pod, kv-e2e-workload/Pod/hostpath-docker-sock, kv-e2e-workload/Pod/hostpath-docker-sock, kv-e2e-workload/Pod/hostpath-docker-sock, kv-e2e-workload/Pod/hostpath-etc, kv-e2e-workload/Pod/hostpath-etc, kv-e2e-workload/Pod/hostpath-etc, kv-e2e-workload/Pod/hostpath-opt-data, kv-e2e-workload/Pod/hostpath-opt-data, kv-e2e-workload/Pod/hostpath-opt-data, kv-e2e-workload/Pod/hostpath-root, kv-e2e-workload/Pod/hostpath-root, kv-e2e-workload/Pod/hostpath-root, kv-e2e-workload/Pod/hostpath-var-log, kv-e2e-workload/Pod/hostpath-var-log, kv-e2e-workload/Pod/hostpath-var-log, kv-e2e-workload/Pod/lifecycle-curl, kv-e2e-workload/Pod/lifecycle-curl, kv-e2e-workload/Pod/lifecycle-curl, kv-e2e-workload/Pod/lifecycle-httpget, kv-e2e-workload/Pod/lifecycle-httpget, kv-e2e-workload/Pod/lifecycle-httpget, kv-e2e-workload/Pod/low-uid-pod, kv-e2e-workload/Pod/low-uid-pod, kv-e2e-workload/Pod/missing-non-root, kv-e2e-workload/Pod/missing-non-root, kv-e2e-workload/Pod/missing-non-root, kv-e2e-workload/Deployment/missing-profiles, kv-e2e-workload/Deployment/missing-profiles, kv-e2e-workload/Deployment/missing-profiles, kv-e2e-workload/Deployment/missing-profiles, kv-e2e-workload/Pod/no-startup-probe, kv-e2e-workload/Pod/no-startup-probe, kv-e2e-workload/Pod/no-startup-probe, kv-e2e-workload/Pod/priv-escalation-selinux, kv-e2e-workload/Pod/priv-escalation-selinux, kv-e2e-workload/Pod/priv-escalation-selinux, kv-e2e-workload/Deployment/privileged-container, kv-e2e-workload/Deployment/privileged-container, kv-e2e-workload/Deployment/privileged-container, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Pod/unmasked-proc, kv-e2e-workload/Pod/unmasked-proc, kv-e2e-workload/Pod/unmasked-proc, kv-e2e-workload/Pod/unsafe-sysctls-shared-pid, kv-e2e-workload/Pod/unsafe-sysctls-shared-pid, kv-e2e-workload/Pod/unsafe-sysctls-shared-pid, kv-e2e-workload/Deployment/writable-rootfs, kv-e2e-workload/Deployment/writable-rootfs, kv-e2e-workload/Deployment/writable-rootfs, kv-e2e-workload/Deployment/writable-rootfs, kv-e2e-workload/Deployment/writable-rootfs, kv-e2e-workload/Deployment/writable-rootfs

</details>

<details>
<summary>Remediation: read-only-rootfs (35 resources affected)</summary>

## Why This Matters

A writable root filesystem allows an attacker who gains code execution in your container to modify application binaries, install attack tools, plant backdoors, or persist malware across container restarts. Making the filesystem read-only eliminates an entire class of post-exploitation techniques.

## How to Fix

Enable a read-only root filesystem and mount writable volumes only where needed:

```yaml
securityContext:
  readOnlyRootFilesystem: true
volumeMounts:
  - name: tmp
    mountPath: /tmp
volumes:
  - name: tmp
    emptyDir: {}
```

Common paths that need write access include /tmp, /var/cache, and /var/run. Mount each as an emptyDir or tmpfs volume rather than making the entire filesystem writable.

## Learn More

This aligns with CIS Benchmark 5.2.4 and the defense-in-depth principle. Combined with dropping capabilities and running as non-root, a read-only filesystem forms a strong container hardening baseline.

**Affected resources:** kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Pod/default-sa-automount, kv-e2e-workload/Pod/explicit-default-sa, kv-e2e-workload/Pod/explicit-root, kv-e2e-workload/Pod/host-ipc-pod, kv-e2e-workload/Pod/host-network-pod, kv-e2e-workload/Pod/host-pid-pod, kv-e2e-workload/Pod/host-port-pod, kv-e2e-workload/Pod/hostpath-docker-sock, kv-e2e-workload/Pod/hostpath-etc, kv-e2e-workload/Pod/hostpath-opt-data, kv-e2e-workload/Pod/hostpath-root, kv-e2e-workload/Pod/hostpath-var-log, kv-e2e-workload/Pod/lifecycle-curl, kv-e2e-workload/Pod/lifecycle-httpget, kv-e2e-workload/Pod/low-uid-pod, kv-e2e-workload/Pod/missing-non-root, kv-e2e-workload/Deployment/missing-profiles, kv-e2e-workload/Deployment/missing-profiles, kv-e2e-workload/Pod/no-startup-probe, kv-e2e-workload/Pod/priv-escalation-selinux, kv-e2e-workload/Deployment/privileged-container, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Pod/unmasked-proc, kv-e2e-workload/Pod/unsafe-sysctls-shared-pid, kv-e2e-workload/Deployment/writable-rootfs, kv-e2e-workload/Deployment/writable-rootfs

</details>

<details>
<summary>Remediation: resource-limits-missing (33 resources affected)</summary>

## Why This Matters

Without resource limits, a single container can consume all available CPU and memory on a node, starving other workloads and triggering cascading failures. An attacker who compromises an unlimited container can mount a denial-of-service attack against the entire node with a simple fork bomb or memory allocation loop.

## How to Fix

Set both CPU and memory limits based on your application's actual resource usage:

```yaml
resources:
  limits:
    cpu: 500m
    memory: 256Mi
  requests:
    cpu: 100m
    memory: 128Mi
```

Profile your application under load to determine appropriate values. Set limits to handle peak usage and requests to match steady-state consumption.

## Learn More

Use LimitRange objects to enforce default limits at the namespace level. Resource limits also determine the pod's QoS class: pods with equal requests and limits get Guaranteed QoS and are last to be evicted.

**Affected resources:** kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Pod/default-sa-automount, kv-e2e-workload/Pod/explicit-default-sa, kv-e2e-workload/Pod/explicit-root, kv-e2e-workload/Pod/host-ipc-pod, kv-e2e-workload/Pod/host-network-pod, kv-e2e-workload/Pod/host-pid-pod, kv-e2e-workload/Pod/host-port-pod, kv-e2e-workload/Pod/hostpath-docker-sock, kv-e2e-workload/Pod/hostpath-etc, kv-e2e-workload/Pod/hostpath-opt-data, kv-e2e-workload/Pod/hostpath-root, kv-e2e-workload/Pod/hostpath-var-log, kv-e2e-workload/Pod/lifecycle-curl, kv-e2e-workload/Pod/lifecycle-httpget, kv-e2e-workload/Pod/low-uid-pod, kv-e2e-workload/Pod/missing-non-root, kv-e2e-workload/Deployment/missing-profiles, kv-e2e-workload/Deployment/missing-profiles, kv-e2e-workload/Pod/no-startup-probe, kv-e2e-workload/Pod/priv-escalation-selinux, kv-e2e-workload/Deployment/privileged-container, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Pod/unmasked-proc, kv-e2e-workload/Pod/unsafe-sysctls-shared-pid, kv-e2e-workload/Deployment/writable-rootfs, kv-e2e-workload/Deployment/writable-rootfs

</details>

<details>
<summary>Remediation: resource-requests-missing (33 resources affected)</summary>

## Why This Matters

Resource requests tell the Kubernetes scheduler how much CPU and memory your container needs. Without requests, the scheduler treats the pod as needing zero resources and may pack too many pods onto a single node. This leads to overcommitment, resource contention, throttling, and OOM kills under load.

## How to Fix

Set resource requests based on your application's steady-state usage:

```yaml
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 256Mi
```

Observe your application's actual resource consumption using `kubectl top` or a monitoring tool, then set requests to match the typical steady-state usage.

## Learn More

Resource requests determine the pod's QoS class and scheduling behavior. Pods with requests equal to limits receive Guaranteed QoS. Use Vertical Pod Autoscaler (VPA) to automatically recommend request values.

**Affected resources:** kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Pod/default-sa-automount, kv-e2e-workload/Pod/explicit-default-sa, kv-e2e-workload/Pod/explicit-root, kv-e2e-workload/Pod/host-ipc-pod, kv-e2e-workload/Pod/host-network-pod, kv-e2e-workload/Pod/host-pid-pod, kv-e2e-workload/Pod/host-port-pod, kv-e2e-workload/Pod/hostpath-docker-sock, kv-e2e-workload/Pod/hostpath-etc, kv-e2e-workload/Pod/hostpath-opt-data, kv-e2e-workload/Pod/hostpath-root, kv-e2e-workload/Pod/hostpath-var-log, kv-e2e-workload/Pod/lifecycle-curl, kv-e2e-workload/Pod/lifecycle-httpget, kv-e2e-workload/Pod/low-uid-pod, kv-e2e-workload/Pod/missing-non-root, kv-e2e-workload/Deployment/missing-profiles, kv-e2e-workload/Deployment/missing-profiles, kv-e2e-workload/Pod/no-startup-probe, kv-e2e-workload/Pod/priv-escalation-selinux, kv-e2e-workload/Deployment/privileged-container, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Pod/unmasked-proc, kv-e2e-workload/Pod/unsafe-sysctls-shared-pid, kv-e2e-workload/Deployment/writable-rootfs, kv-e2e-workload/Deployment/writable-rootfs

</details>

<details>
<summary>Remediation: run-as-group (35 resources affected)</summary>

## Why This Matters

Without an explicit runAsGroup, the container process defaults to GID 0 (the root group). Files and sockets owned by the root group become accessible to the container, including potentially sensitive host files if volumes are mounted. This widens the attack surface unnecessarily.

## How to Fix

Set an explicit non-root group in the securityContext:

```yaml
securityContext:
  runAsGroup: 1000
  runAsUser: 1000
  runAsNonRoot: true
```

Ensure the container image's application files and directories are readable by the specified GID. You may need to adjust file ownership in your Dockerfile with `chown`.

## Learn More

This aligns with CIS Benchmark 5.2.6 and the Pod Security Standards "Restricted" profile. Always set runAsUser, runAsGroup, and runAsNonRoot together for comprehensive identity control.

**Affected resources:** kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Pod/default-sa-automount, kv-e2e-workload/Pod/explicit-default-sa, kv-e2e-workload/Pod/explicit-root, kv-e2e-workload/Pod/host-ipc-pod, kv-e2e-workload/Pod/host-network-pod, kv-e2e-workload/Pod/host-pid-pod, kv-e2e-workload/Pod/host-port-pod, kv-e2e-workload/Pod/hostpath-docker-sock, kv-e2e-workload/Pod/hostpath-etc, kv-e2e-workload/Pod/hostpath-opt-data, kv-e2e-workload/Pod/hostpath-root, kv-e2e-workload/Pod/hostpath-var-log, kv-e2e-workload/Pod/lifecycle-curl, kv-e2e-workload/Pod/lifecycle-httpget, kv-e2e-workload/Pod/low-uid-pod, kv-e2e-workload/Pod/missing-non-root, kv-e2e-workload/Deployment/missing-profiles, kv-e2e-workload/Deployment/missing-profiles, kv-e2e-workload/Pod/no-startup-probe, kv-e2e-workload/Pod/priv-escalation-selinux, kv-e2e-workload/Deployment/privileged-container, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Pod/unmasked-proc, kv-e2e-workload/Pod/unsafe-sysctls-shared-pid, kv-e2e-workload/Deployment/writable-rootfs, kv-e2e-workload/Deployment/writable-rootfs

</details>

<details>
<summary>Remediation: seccomp-profile (34 resources affected)</summary>

## Why This Matters

Without a Seccomp profile, containers can invoke any of the 300+ Linux system calls, leaving the entire kernel attack surface exposed. Kernel vulnerabilities in obscure syscalls are a primary vector for container escapes. Seccomp filtering blocks dangerous syscalls that legitimate applications never use.

## How to Fix

Apply a Seccomp profile at the container or pod level:

```yaml
securityContext:
  seccompProfile:
    type: RuntimeDefault
```

The RuntimeDefault profile blocks approximately 50 dangerous syscalls while allowing normal application behavior. For stricter controls, use a custom Localhost profile tailored to your application's needs. Set the profile at the pod level to apply it to all containers.

## Learn More

Seccomp profiles are required by the Pod Security Standards "Restricted" profile and CIS Benchmark 5.7.2. Use tools like `strace` or the Security Profiles Operator to generate custom profiles for your workloads.

**Affected resources:** kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Pod/default-sa-automount, kv-e2e-workload/Pod/explicit-default-sa, kv-e2e-workload/Pod/explicit-root, kv-e2e-workload/Pod/host-ipc-pod, kv-e2e-workload/Pod/host-network-pod, kv-e2e-workload/Pod/host-pid-pod, kv-e2e-workload/Pod/host-port-pod, kv-e2e-workload/Pod/hostpath-docker-sock, kv-e2e-workload/Pod/hostpath-etc, kv-e2e-workload/Pod/hostpath-opt-data, kv-e2e-workload/Pod/hostpath-root, kv-e2e-workload/Pod/hostpath-var-log, kv-e2e-workload/Pod/lifecycle-curl, kv-e2e-workload/Pod/lifecycle-httpget, kv-e2e-workload/Pod/low-uid-pod, kv-e2e-workload/Pod/missing-non-root, kv-e2e-workload/Deployment/missing-profiles, kv-e2e-workload/Pod/no-startup-probe, kv-e2e-workload/Pod/priv-escalation-selinux, kv-e2e-workload/Deployment/privileged-container, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Pod/unmasked-proc, kv-e2e-workload/Pod/unsafe-sysctls-shared-pid, kv-e2e-workload/Deployment/writable-rootfs, kv-e2e-workload/Deployment/writable-rootfs

</details>

<details>
<summary>Remediation: token-projection-config (6 resources affected)</summary>

## Why This Matters

Without explicit projection configuration, ServiceAccount tokens use Kubernetes defaults: no audience restriction and a long expiration. A stolen token remains valid for an extended period and can be used against any API server endpoint, widening the blast radius of a compromise.

## How to Fix

Add a projected volume with explicit expiration and audience:

```yaml
spec:
  volumes:
    - name: token
      projected:
        sources:
          - serviceAccountToken:
              expirationSeconds: 3600
              audience: my-api
              path: token
  containers:
    - name: app
      volumeMounts:
        - name: token
          mountPath: /var/run/secrets/tokens
          readOnly: true
```

Projected tokens auto-rotate before expiry and are rejected by endpoints outside the specified audience.

## Learn More

See the Kubernetes documentation on projected volumes and service account token volume projection for detailed configuration options.

**Affected resources:** kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Deployment/missing-profiles, kv-e2e-workload/Deployment/privileged-container, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/writable-rootfs

</details>

<details>
<summary>Remediation: projected-volume-security (20 resources affected)</summary>

## Why This Matters

Projected volumes with overly permissive file modes allow any process in the pod to read sensitive data such as service account tokens and secrets. If a container is compromised, the attacker can easily harvest these credentials to escalate privileges or move laterally within the cluster.

## How to Fix

Reduce the defaultMode to restrict file access:

```yaml
spec:
  volumes:
    - name: kube-api-access-z5rjm
      projected:
        defaultMode: 0400         # Owner read-only (was too permissive)
        sources:
          - serviceAccountToken:
              path: token
```

Use 0400 for read-only access or 0600 if the application must write to the mounted files.

## Learn More

See the Kubernetes Projected Volumes documentation for defaultMode details. The CIS Benchmark recommends file modes of 0600 or lower for sensitive volume mounts to limit exposure within the pod.

**Affected resources:** kv-e2e-workload/Pod/default-sa-automount, kv-e2e-workload/Pod/explicit-default-sa, kv-e2e-workload/Pod/explicit-root, kv-e2e-workload/Pod/host-ipc-pod, kv-e2e-workload/Pod/host-network-pod, kv-e2e-workload/Pod/host-pid-pod, kv-e2e-workload/Pod/host-port-pod, kv-e2e-workload/Pod/hostpath-docker-sock, kv-e2e-workload/Pod/hostpath-etc, kv-e2e-workload/Pod/hostpath-opt-data, kv-e2e-workload/Pod/hostpath-root, kv-e2e-workload/Pod/hostpath-var-log, kv-e2e-workload/Pod/lifecycle-curl, kv-e2e-workload/Pod/lifecycle-httpget, kv-e2e-workload/Pod/low-uid-pod, kv-e2e-workload/Pod/missing-non-root, kv-e2e-workload/Pod/no-startup-probe, kv-e2e-workload/Pod/priv-escalation-selinux, kv-e2e-workload/Pod/unmasked-proc, kv-e2e-workload/Pod/unsafe-sysctls-shared-pid

</details>

<details>
<summary>Remediation: network-policy-egress-unrestricted (1 resources affected)</summary>

## Why This Matters

Without any egress NetworkPolicy in this namespace, pods can freely send traffic to any destination including the public internet. A compromised pod can exfiltrate sensitive data, reach cloud metadata services (e.g., 169.254.169.254), or establish reverse shells to attacker-controlled servers.

## How to Fix

Create a NetworkPolicy with `Egress` in `policyTypes` to restrict outbound traffic. At minimum, allow DNS resolution:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-egress
  namespace: my-namespace
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector: {}
      ports:
        - port: 53
          protocol: UDP
```

Add additional egress rules for specific services your workloads need to reach.

## Learn More

See the Kubernetes NetworkPolicy documentation and CIS Kubernetes Benchmark 5.3.2. Egress controls are a key defense-in-depth measure recommended by the NSA/CISA Kubernetes Hardening Guide.

**Affected resources:** kv-e2e-workload/Namespace/kv-e2e-workload

</details>

<details>
<summary>Remediation: psa-labels-missing (1 resources affected)</summary>

## Why This Matters

Without PSA enforcement labels, any pod configuration is allowed in this namespace, including privileged containers, host namespace access, and root execution. This bypasses Kubernetes' built-in Pod Security Standards and leaves the namespace vulnerable to workloads that could compromise the node.

## How to Fix

Add Pod Security Admission labels to enforce a security profile on all pods in the namespace:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: kv-e2e-workload
  labels:
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

Start with `baseline` enforcement to block known privilege escalations, then upgrade to `restricted` after verifying all workloads are compliant.

## Learn More

See the Kubernetes Pod Security Admission documentation and CIS Kubernetes Benchmark 5.2. The three-tier approach (enforce, audit, warn) allows gradual adoption of stricter profiles.

**Affected resources:** kv-e2e-workload/Namespace/kv-e2e-workload

</details>

<details>
<summary>Remediation: selinux-options (1 resources affected)</summary>

## Why This Matters

SELinux types like `spc_t` (super privileged container) and `unconfined_t` completely disable SELinux mandatory access control for the container. On RHEL, CentOS, and Fedora nodes where SELinux is enforcing, this removes a critical security boundary that prevents containers from accessing host files, devices, and other container data even after a compromise.

## How to Fix

Remove the dangerous SELinux type or use the default confined context:

```yaml
securityContext:
  seLinuxOptions:
    type: ""  # Use default confined context
  # Or remove seLinuxOptions entirely
```

If your application needs specific SELinux access, create a custom policy rather than disabling confinement entirely. Test in a non-production environment first.

## Learn More

SELinux enforcement is a key defense layer on RHEL-family nodes. The `spc_t` type is equivalent to disabling SELinux for that container. Refer to CIS Benchmark 5.7.3 and the OpenShift SELinux documentation.

**Affected resources:** kv-e2e-workload/Pod/priv-escalation-selinux

</details>

<details>
<summary>Remediation: share-process-namespace (1 resources affected)</summary>

## Why This Matters

When shareProcessNamespace is enabled, all containers in the pod share the same PID namespace and can see each other's processes, access their /proc entries, and send signals. If one container is compromised, the attacker can inspect environment variables, read memory via /proc/[pid]/mem, or kill processes in sibling containers.

## How to Fix

Disable process namespace sharing unless explicitly required:

```yaml
spec:
  shareProcessNamespace: false
```

Legitimate use cases for shared PID namespaces include sidecar containers that need to monitor the main application process, or debug containers that need process visibility. Evaluate whether your sidecar pattern truly requires this access.

## Learn More

Shared PID namespaces also make PID 1 the pause container rather than your application, which changes signal handling behavior. See the Kubernetes documentation on sharing process namespace between containers.

**Affected resources:** kv-e2e-workload/Pod/unsafe-sysctls-shared-pid

</details>

<details>
<summary>Remediation: ephemeral-storage-limits (35 resources affected)</summary>

## Why This Matters

Ephemeral storage includes container logs, emptyDir volumes, and the writable container layer. Without limits, a single container can fill the node's root disk, triggering eviction of all pods on that node and potentially causing a cascading failure across your cluster. This is a common denial-of-service vector.

## How to Fix

Set ephemeral-storage limits alongside your CPU and memory limits:

```yaml
resources:
  limits:
    ephemeral-storage: 1Gi
  requests:
    ephemeral-storage: 500Mi
```

Estimate your application's disk usage from logs, temporary files, and cache data. If your application writes large temporary files, consider using a PersistentVolumeClaim instead of ephemeral storage.

## Learn More

The kubelet evicts pods that exceed their ephemeral-storage limit. Use LimitRange to set default ephemeral-storage limits at the namespace level to catch containers that omit this setting.

**Affected resources:** kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Pod/default-sa-automount, kv-e2e-workload/Pod/explicit-default-sa, kv-e2e-workload/Pod/explicit-root, kv-e2e-workload/Pod/host-ipc-pod, kv-e2e-workload/Pod/host-network-pod, kv-e2e-workload/Pod/host-pid-pod, kv-e2e-workload/Pod/host-port-pod, kv-e2e-workload/Pod/hostpath-docker-sock, kv-e2e-workload/Pod/hostpath-etc, kv-e2e-workload/Pod/hostpath-opt-data, kv-e2e-workload/Pod/hostpath-root, kv-e2e-workload/Pod/hostpath-var-log, kv-e2e-workload/Pod/lifecycle-curl, kv-e2e-workload/Pod/lifecycle-httpget, kv-e2e-workload/Pod/low-uid-pod, kv-e2e-workload/Pod/missing-non-root, kv-e2e-workload/Deployment/missing-profiles, kv-e2e-workload/Deployment/missing-profiles, kv-e2e-workload/Pod/no-startup-probe, kv-e2e-workload/Pod/priv-escalation-selinux, kv-e2e-workload/Deployment/privileged-container, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Pod/unmasked-proc, kv-e2e-workload/Pod/unsafe-sysctls-shared-pid, kv-e2e-workload/Deployment/writable-rootfs, kv-e2e-workload/Deployment/writable-rootfs

</details>

<details>
<summary>Remediation: image-no-digest (35 resources affected)</summary>

## Why This Matters

Image tags are mutable pointers -- a registry administrator or attacker can re-push a different image under the same tag. Without a digest, you have no cryptographic guarantee that the image you deploy is the one you tested.

## How to Fix

Pin images by their SHA-256 content digest for a fully immutable reference:

```yaml
containers:
  - name: app
    image: nginx@sha256:a8281ce420348a01ea6e   # Immutable
```

Use `crane digest nginx:1.25.3` or `skopeo inspect` to resolve a tag to its digest during CI/CD, then commit the pinned reference.

## Learn More

SLSA Level 1+ and NIST SP 800-190 recommend digest pinning for container supply chain integrity. See the Kubernetes images documentation for details.

**Affected resources:** kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Pod/default-sa-automount, kv-e2e-workload/Pod/explicit-default-sa, kv-e2e-workload/Pod/explicit-root, kv-e2e-workload/Pod/host-ipc-pod, kv-e2e-workload/Pod/host-network-pod, kv-e2e-workload/Pod/host-pid-pod, kv-e2e-workload/Pod/host-port-pod, kv-e2e-workload/Pod/hostpath-docker-sock, kv-e2e-workload/Pod/hostpath-etc, kv-e2e-workload/Pod/hostpath-opt-data, kv-e2e-workload/Pod/hostpath-root, kv-e2e-workload/Pod/hostpath-var-log, kv-e2e-workload/Pod/lifecycle-curl, kv-e2e-workload/Pod/lifecycle-httpget, kv-e2e-workload/Pod/low-uid-pod, kv-e2e-workload/Pod/missing-non-root, kv-e2e-workload/Deployment/missing-profiles, kv-e2e-workload/Deployment/missing-profiles, kv-e2e-workload/Pod/no-startup-probe, kv-e2e-workload/Pod/priv-escalation-selinux, kv-e2e-workload/Deployment/privileged-container, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Pod/unmasked-proc, kv-e2e-workload/Pod/unsafe-sysctls-shared-pid, kv-e2e-workload/Deployment/writable-rootfs, kv-e2e-workload/Deployment/writable-rootfs

</details>

<details>
<summary>Remediation: liveness-readiness-probes (69 resources affected)</summary>

## Why This Matters

Without a liveness probe, Kubernetes cannot detect when a container has become unresponsive or deadlocked. The container continues running and consuming resources while failing to serve traffic. Users experience timeouts and errors until someone manually intervenes.

## How to Fix

Add a liveness probe that checks the container's health:

```yaml
containers:
  - name: app
    livenessProbe:
      httpGet:
        path: /healthz
        port: 8080
      initialDelaySeconds: 15
      periodSeconds: 10
      failureThreshold: 3
```

Use `httpGet` for HTTP services, `tcpSocket` for TCP services, or `exec` with a custom health check script for non-network workloads.

## Learn More

See the Kubernetes documentation on container probes. Set initialDelaySeconds high enough for your application to start, and consider adding a startupProbe for slow-starting containers.

**Affected resources:** kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Pod/default-sa-automount, kv-e2e-workload/Pod/default-sa-automount, kv-e2e-workload/Pod/explicit-default-sa, kv-e2e-workload/Pod/explicit-default-sa, kv-e2e-workload/Pod/explicit-root, kv-e2e-workload/Pod/explicit-root, kv-e2e-workload/Pod/host-ipc-pod, kv-e2e-workload/Pod/host-ipc-pod, kv-e2e-workload/Pod/host-network-pod, kv-e2e-workload/Pod/host-network-pod, kv-e2e-workload/Pod/host-pid-pod, kv-e2e-workload/Pod/host-pid-pod, kv-e2e-workload/Pod/host-port-pod, kv-e2e-workload/Pod/host-port-pod, kv-e2e-workload/Pod/hostpath-docker-sock, kv-e2e-workload/Pod/hostpath-docker-sock, kv-e2e-workload/Pod/hostpath-etc, kv-e2e-workload/Pod/hostpath-etc, kv-e2e-workload/Pod/hostpath-opt-data, kv-e2e-workload/Pod/hostpath-opt-data, kv-e2e-workload/Pod/hostpath-root, kv-e2e-workload/Pod/hostpath-root, kv-e2e-workload/Pod/hostpath-var-log, kv-e2e-workload/Pod/hostpath-var-log, kv-e2e-workload/Pod/lifecycle-curl, kv-e2e-workload/Pod/lifecycle-curl, kv-e2e-workload/Pod/lifecycle-httpget, kv-e2e-workload/Pod/lifecycle-httpget, kv-e2e-workload/Pod/low-uid-pod, kv-e2e-workload/Pod/low-uid-pod, kv-e2e-workload/Pod/missing-non-root, kv-e2e-workload/Pod/missing-non-root, kv-e2e-workload/Deployment/missing-profiles, kv-e2e-workload/Deployment/missing-profiles, kv-e2e-workload/Deployment/missing-profiles, kv-e2e-workload/Deployment/missing-profiles, kv-e2e-workload/Pod/no-startup-probe, kv-e2e-workload/Pod/priv-escalation-selinux, kv-e2e-workload/Pod/priv-escalation-selinux, kv-e2e-workload/Deployment/privileged-container, kv-e2e-workload/Deployment/privileged-container, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Pod/unmasked-proc, kv-e2e-workload/Pod/unmasked-proc, kv-e2e-workload/Pod/unsafe-sysctls-shared-pid, kv-e2e-workload/Pod/unsafe-sysctls-shared-pid, kv-e2e-workload/Deployment/writable-rootfs, kv-e2e-workload/Deployment/writable-rootfs, kv-e2e-workload/Deployment/writable-rootfs, kv-e2e-workload/Deployment/writable-rootfs

</details>

<details>
<summary>Remediation: priority-class-missing (26 resources affected)</summary>

## Why This Matters

Without a PriorityClass, pods receive default priority (typically 0) and are among the first to be evicted during resource pressure or node maintenance. This means important application workloads may be killed before less critical ones, leading to unpredictable outages.

## How to Fix

Define PriorityClasses for your workloads and assign them appropriately:

```yaml
apiVersion: scheduling.k8s.io/v1
kind: PriorityClass
metadata:
  name: app-medium
value: 100000
---
# Reference in your workload:
spec:
  priorityClassName: app-medium
```

Create a tiered priority scheme (e.g., app-critical: 500000, app-medium: 100000, app-low: 10000) that reflects your workload importance hierarchy.

## Learn More

Refer to the Kubernetes Pod Priority and Preemption documentation. Establishing a consistent priority scheme across namespaces ensures predictable eviction behavior during resource contention.

**Affected resources:** kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Pod/default-sa-automount, kv-e2e-workload/Pod/explicit-default-sa, kv-e2e-workload/Pod/explicit-root, kv-e2e-workload/Pod/host-ipc-pod, kv-e2e-workload/Pod/host-network-pod, kv-e2e-workload/Pod/host-pid-pod, kv-e2e-workload/Pod/host-port-pod, kv-e2e-workload/Pod/hostpath-docker-sock, kv-e2e-workload/Pod/hostpath-etc, kv-e2e-workload/Pod/hostpath-opt-data, kv-e2e-workload/Pod/hostpath-root, kv-e2e-workload/Pod/hostpath-var-log, kv-e2e-workload/Pod/lifecycle-curl, kv-e2e-workload/Pod/lifecycle-httpget, kv-e2e-workload/Pod/low-uid-pod, kv-e2e-workload/Pod/missing-non-root, kv-e2e-workload/Deployment/missing-profiles, kv-e2e-workload/Pod/no-startup-probe, kv-e2e-workload/Pod/priv-escalation-selinux, kv-e2e-workload/Deployment/privileged-container, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Pod/unmasked-proc, kv-e2e-workload/Pod/unsafe-sysctls-shared-pid, kv-e2e-workload/Deployment/writable-rootfs

</details>

<details>
<summary>Remediation: runtime-class (26 resources affected)</summary>

## Why This Matters

Without a RuntimeClass, pods use the default container runtime (typically runc), which shares the host kernel directly with containers. A kernel vulnerability can allow container escape to the host. Sandboxed runtimes like gVisor or Kata Containers add an additional isolation layer that intercepts system calls or runs containers in lightweight VMs.

## How to Fix

Specify a sandboxed RuntimeClass in the pod spec:

```yaml
spec:
  runtimeClassName: gvisor
```

Available RuntimeClasses depend on your cluster configuration. Common options include `gvisor` (user-space kernel), `kata` (micro-VMs), and `firecracker`. Check your cluster's available RuntimeClasses with `kubectl get runtimeclasses`.

## Learn More

Sandboxed runtimes are especially important for multi-tenant clusters and workloads processing untrusted input. They add latency overhead, so evaluate performance requirements. See the Kubernetes RuntimeClass documentation.

**Affected resources:** kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Pod/default-sa-automount, kv-e2e-workload/Pod/explicit-default-sa, kv-e2e-workload/Pod/explicit-root, kv-e2e-workload/Pod/host-ipc-pod, kv-e2e-workload/Pod/host-network-pod, kv-e2e-workload/Pod/host-pid-pod, kv-e2e-workload/Pod/host-port-pod, kv-e2e-workload/Pod/hostpath-docker-sock, kv-e2e-workload/Pod/hostpath-etc, kv-e2e-workload/Pod/hostpath-opt-data, kv-e2e-workload/Pod/hostpath-root, kv-e2e-workload/Pod/hostpath-var-log, kv-e2e-workload/Pod/lifecycle-curl, kv-e2e-workload/Pod/lifecycle-httpget, kv-e2e-workload/Pod/low-uid-pod, kv-e2e-workload/Pod/missing-non-root, kv-e2e-workload/Deployment/missing-profiles, kv-e2e-workload/Pod/no-startup-probe, kv-e2e-workload/Pod/priv-escalation-selinux, kv-e2e-workload/Deployment/privileged-container, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Pod/unmasked-proc, kv-e2e-workload/Pod/unsafe-sysctls-shared-pid, kv-e2e-workload/Deployment/writable-rootfs

</details>

<details>
<summary>Remediation: topology-spread (26 resources affected)</summary>

## Why This Matters

Without topology spread constraints, the scheduler may place all replicas on the same node or in the same availability zone. If that node or zone fails, your entire service goes down despite having multiple replicas. This negates the high-availability benefits of running multiple pods.

## How to Fix

Add topology spread constraints to distribute replicas across failure domains:

```yaml
spec:
  topologySpreadConstraints:
    - maxSkew: 1
      topologyKey: kubernetes.io/hostname
      whenUnsatisfiable: DoNotSchedule
      labelSelector:
        matchLabels:
          app: my-app
    - maxSkew: 1
      topologyKey: topology.kubernetes.io/zone
      whenUnsatisfiable: ScheduleAnyway
```

Use `kubernetes.io/hostname` for node-level spreading and `topology.kubernetes.io/zone` for zone-level spreading.

## Learn More

See the Kubernetes Pod Topology Spread Constraints documentation. Combining hostname and zone constraints provides both node-level and zone-level fault tolerance.

**Affected resources:** kv-e2e-workload/Deployment/dangerous-capabilities, kv-e2e-workload/Pod/default-sa-automount, kv-e2e-workload/Pod/explicit-default-sa, kv-e2e-workload/Pod/explicit-root, kv-e2e-workload/Pod/host-ipc-pod, kv-e2e-workload/Pod/host-network-pod, kv-e2e-workload/Pod/host-pid-pod, kv-e2e-workload/Pod/host-port-pod, kv-e2e-workload/Pod/hostpath-docker-sock, kv-e2e-workload/Pod/hostpath-etc, kv-e2e-workload/Pod/hostpath-opt-data, kv-e2e-workload/Pod/hostpath-root, kv-e2e-workload/Pod/hostpath-var-log, kv-e2e-workload/Pod/lifecycle-curl, kv-e2e-workload/Pod/lifecycle-httpget, kv-e2e-workload/Pod/low-uid-pod, kv-e2e-workload/Pod/missing-non-root, kv-e2e-workload/Deployment/missing-profiles, kv-e2e-workload/Pod/no-startup-probe, kv-e2e-workload/Pod/priv-escalation-selinux, kv-e2e-workload/Deployment/privileged-container, kv-e2e-workload/Deployment/pull-policy-issues, kv-e2e-workload/Deployment/resource-issues, kv-e2e-workload/Pod/unmasked-proc, kv-e2e-workload/Pod/unsafe-sysctls-shared-pid, kv-e2e-workload/Deployment/writable-rootfs

</details>

<details>
<summary>Remediation: limit-range-missing (1 resources affected)</summary>

## Why This Matters

Without a LimitRange, any container can be created without resource constraints. A single runaway or malicious pod can consume all node CPU and memory, causing denial of service for other workloads on the same node.

## How to Fix

Create a LimitRange in the namespace to set default and maximum resource constraints:

```yaml
apiVersion: v1
kind: LimitRange
metadata:
  name: default-limits
  namespace: my-app
spec:
  limits:
    - type: Container
      default:
        cpu: 500m
        memory: 256Mi
      defaultRequest:
        cpu: 100m
        memory: 128Mi
      max:
        cpu: "2"
        memory: 1Gi
```

Containers that omit resource requests/limits will inherit these defaults automatically.

## Learn More

CIS Kubernetes Benchmark 5.2.1 recommends LimitRanges for resource governance. See https://kubernetes.io/docs/concepts/policy/limit-range/ for configuration details.

**Affected resources:** kv-e2e-workload/Namespace/kv-e2e-workload

</details>

<details>
<summary>Remediation: resource-quota-missing (1 resources affected)</summary>

## Why This Matters

Without a ResourceQuota, a single namespace can consume the entire cluster's CPU, memory, and storage. This creates a noisy-neighbor problem where one team's workloads starve others, and makes capacity planning impossible.

## How to Fix

Create a ResourceQuota to cap the namespace's total resource consumption:

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: compute-quota
  namespace: my-app
spec:
  hard:
    requests.cpu: "10"
    requests.memory: 20Gi
    limits.cpu: "20"
    limits.memory: 40Gi
    pods: "50"
    services: "10"
```

Tune quota values based on the namespace's actual workload requirements and cluster capacity.

## Learn More

CIS Kubernetes Benchmark 5.2.2 recommends ResourceQuotas for multi-tenant clusters. See https://kubernetes.io/docs/concepts/policy/resource-quotas/ for quota configuration and enforcement behavior.

**Affected resources:** kv-e2e-workload/Namespace/kv-e2e-workload

</details>

<details>
<summary>Remediation: lifecycle-hooks (2 resources affected)</summary>

## Why This Matters

PreStop hooks that make network calls (curl, wget, HTTP requests) can be exploited for data exfiltration during pod termination. An attacker who modifies a deployment can add a preStop hook that sends sensitive data to an external server every time a pod is terminated, scaled down, or restarted.

## How to Fix

Replace network-calling preStop hooks with local-only cleanup operations:

```yaml
lifecycle:
  preStop:
    exec:
      command:
        - /bin/sh
        - -c
        - "kill -SIGTERM 1 && sleep 5"  # Graceful local shutdown
```

If external notification is truly required, use a sidecar or controller pattern with egress network policies restricting the destination.

## Learn More

See MITRE ATT&CK T1020 (Automated Exfiltration) for data exfiltration techniques. Network policies should restrict egress for pods that do not need external access.

**Affected resources:** kv-e2e-workload/Pod/lifecycle-curl, kv-e2e-workload/Pod/lifecycle-httpget

</details>

<details>
<summary>Remediation: run-as-high-uid (1 resources affected)</summary>

## Why This Matters

UIDs below 10000 overlap with well-known system accounts on most Linux distributions (e.g., daemon, www-data, nobody). If a container running with a low UID escapes to the host, it may inherit the permissions of that system account, gaining unintended access to host files, sockets, or services owned by that UID.

## How to Fix

Use a high UID that does not overlap with host system accounts:

```yaml
securityContext:
  runAsUser: 65534       # nobody, or any UID >= 10000
  runAsNonRoot: true
  runAsGroup: 65534
```

Choose a UID >= 10000. The conventional `nobody` UID (65534) is a safe default. Also set the UID in your Dockerfile with `USER 65534` for defense in depth.

## Learn More

This is a defense-in-depth measure. While container UID mapping varies by runtime, using high UIDs avoids accidental privilege overlap on hosts that lack user namespace remapping.

**Affected resources:** kv-e2e-workload/Pod/low-uid-pod

</details>

<details>
<summary>Remediation: resource-limits-ratio (1 resources affected)</summary>

## Why This Matters

When resource limits are much higher than requests, the scheduler allocates nodes based on the smaller request values but containers can burst up to their limits. If multiple containers burst simultaneously, the node becomes overcommitted, leading to CPU throttling and OOM kills that cause unpredictable application failures.

## How to Fix

Bring limits closer to requests, ideally within a 3x ratio:

```yaml
resources:
  requests:
    cpu: 200m
    memory: 256Mi
  limits:
    cpu: 500m            # 2.5x ratio
    memory: 512Mi        # 2x ratio
```

Profile your application's actual resource usage under realistic load using `kubectl top` or Prometheus metrics, then set requests close to the steady-state and limits for peak bursts.

## Learn More

Consider using Vertical Pod Autoscaler (VPA) to automatically recommend appropriate request and limit values. Setting requests equal to limits gives the pod Guaranteed QoS, providing the most predictable performance.

**Affected resources:** kv-e2e-workload/Deployment/resource-issues

</details>

<details>
<summary>Remediation: startup-probes (1 resources affected)</summary>

## Why This Matters

When a container has a liveness probe but no startup probe, the liveness probe starts checking immediately after the container starts. If the application takes longer to initialize than the liveness probe's initialDelaySeconds + failureThreshold allows, Kubernetes kills and restarts the container, creating an infinite restart loop (CrashLoopBackOff).

## How to Fix

Add a startup probe that gives the container enough time to initialize:

```yaml
containers:
  - name: app
    startupProbe:
      httpGet:
        path: /healthz
        port: 8080
      failureThreshold: 30     # 30 x 10s = 5 minutes to start
      periodSeconds: 10
```

The liveness probe is disabled until the startup probe succeeds, giving slow-starting applications the time they need.

## Learn More

See the Kubernetes startup probe documentation. This is especially important for Java/JVM applications, containers loading large ML models, or services that run database migrations on startup.

**Affected resources:** kv-e2e-workload/Pod/no-startup-probe

</details>

### local-path-storage (31 findings — 🟠8 🟡14 🔵9)

| Severity | Check | Resources | Message | Frameworks |
|----------|-------|-----------|---------|-----------|
| 🟠 High | secrets-in-configmap | **2 resources** | ConfigMap "local-path-config" has high-entropy value in key "setup" (possible secret) | CIS 5.4.1 · MITRE T1552 · NSA 5.1 |
| 🟠 High | automount-token | local-path-storage/Deployment/local-path-provisioner | Deployment "local-path-provisioner" auto-mounts a ServiceAccount token. Most workloads do not need Kubernetes API access. | CIS 5.1.6 · MITRE T1552.007 · NSA 3.2 |
| 🟠 High | privilege-escalation | local-path-storage/Deployment/local-path-provisioner (local-path-provisioner) | Container "local-path-provisioner" does not set allowPrivilegeEscalation to false, permitting privilege escalation. | CIS 5.2.6 · MITRE T1068 · MITRE T1611 · NSA 1.1 · NSA 2.1 |
| 🟠 High | run-as-root | local-path-storage/Deployment/local-path-provisioner (local-path-provisioner) | Container "local-path-provisioner" does not set runAsNonRoot: true and may run as root. | CIS 5.2.7 · MITRE T1611 · NSA 1.1 |
| 🟠 High | toleration-control-plane | **2 resources** | Deployment "local-path-provisioner" tolerates control-plane taint key "node-role.kubernetes.io/control-plane"; only system components should run on control-plane nodes. | CIS 5.6.3 · MITRE T1611 · NSA 1.3 |
| 🟠 High | network-policy-missing | local-path-storage/Namespace/local-path-storage | Namespace "local-path-storage" has no NetworkPolicy defined. All pods are unrestricted. | CIS 5.3.2 · MITRE T1046 · NSA 4.1 · NSA 4.2 |
| 🟡 Medium | apparmor-profile | local-path-storage/Deployment/local-path-provisioner (local-path-provisioner) | Container "local-path-provisioner" does not have an AppArmor profile set. | CIS 5.6.3 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | capabilities-not-dropped | local-path-storage/Deployment/local-path-provisioner (local-path-provisioner) | Container "local-path-provisioner" does not drop ALL capabilities, leaving it with unnecessary default privileges. | CIS 5.2.8 · CIS 5.2.10 · MITRE T1068 · NSA 1.1 |
| 🟡 Medium | image-pull-policy | local-path-storage/Deployment/local-path-provisioner (local-path-provisioner) | Container "local-path-provisioner" uses a mutable image tag with pullPolicy "IfNotPresent" (image: docker.io/kindest/local-path-provisioner:v20251212-v0.29.0-alpha-105-g20ccfc88), risking stale images. | CIS 5.5.1 · MITRE T1525 · NSA 1.4 |
| 🟡 Medium | psa-restricted-violations | **3 resources** | Deployment "local-path-provisioner" container "local-path-provisioner" violates PSS Restricted: runAsNonRoot is not true. | CIS 5.2.1 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | read-only-rootfs | local-path-storage/Deployment/local-path-provisioner (local-path-provisioner) | Container "local-path-provisioner" does not have a read-only root filesystem. | CIS 5.6.3 · MITRE T1565.001 · NSA 1.2 |
| 🟡 Medium | resource-limits-missing | local-path-storage/Deployment/local-path-provisioner (local-path-provisioner) | Container "local-path-provisioner" is missing both CPU and memory limits. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🟡 Medium | resource-requests-missing | local-path-storage/Deployment/local-path-provisioner (local-path-provisioner) | Container "local-path-provisioner" is missing both CPU and memory requests. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🟡 Medium | run-as-group | local-path-storage/Deployment/local-path-provisioner (local-path-provisioner) | Container "local-path-provisioner" does not set runAsGroup; the process will run as GID 0 (root group) by default. | CIS 5.2.7 · MITRE T1068 · NSA 1.1 |
| 🟡 Medium | seccomp-profile | local-path-storage/Deployment/local-path-provisioner (local-path-provisioner) | Container "local-path-provisioner" does not have a Seccomp profile set at either the container or pod level. | CIS 5.6.2 · MITRE T1611 · NSA 2.1 |
| 🟡 Medium | token-projection-config | local-path-storage/Deployment/local-path-provisioner | Deployment "local-path-provisioner" does not use explicitly configured projected ServiceAccount tokens with expiry and audience restrictions. | CIS 5.1.6 · MITRE T1552.007 · NSA 3.2 |
| 🟡 Medium | network-policy-egress-unrestricted | local-path-storage/Namespace/local-path-storage | Namespace "local-path-storage" has no NetworkPolicy with egress restrictions. Pods can reach any external destination. | CIS 5.3.2 · MITRE T1048 · NSA 4.2 |
| 🟡 Medium | psa-labels-missing | local-path-storage/Namespace/local-path-storage | Namespace "local-path-storage" is missing the pod-security.kubernetes.io/enforce label; pod security is not enforced. | CIS 5.2.1 · MITRE T1610 · NSA 2.1 |
| 🔵 Low | ephemeral-storage-limits | local-path-storage/Deployment/local-path-provisioner (local-path-provisioner) | Container "local-path-provisioner" is missing ephemeral-storage limits. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | image-no-digest | local-path-storage/Deployment/local-path-provisioner (local-path-provisioner) | Container "local-path-provisioner" image is not pinned by digest (image: docker.io/kindest/local-path-provisioner:v20251212-v0.29.0-alpha-105-g20ccfc88), allowing tag mutation. | CIS 5.5.1 · MITRE T1525 · NSA 1.4 |
| 🔵 Low | liveness-readiness-probes | **2 resources** | Container "local-path-provisioner" has no liveness probe configured. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | priority-class-missing | local-path-storage/Deployment/local-path-provisioner | Deployment "local-path-provisioner" has no PriorityClass set; it will be evicted first during resource pressure. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | runtime-class | local-path-storage/Deployment/local-path-provisioner | Pod "local-path-provisioner" does not specify a RuntimeClass, using the default (unsandboxed) runtime. | CIS 5.6.3 · MITRE T1611 · NSA 2.1 |
| 🔵 Low | topology-spread | local-path-storage/Deployment/local-path-provisioner | Deployment "local-path-provisioner" has no topology spread constraints; all replicas may be scheduled on the same node. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | limit-range-missing | local-path-storage/Namespace/local-path-storage | Namespace "local-path-storage" has no LimitRange defined. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |
| 🔵 Low | resource-quota-missing | local-path-storage/Namespace/local-path-storage | Namespace "local-path-storage" has no ResourceQuota defined. | CIS 5.6.3 · MITRE T1499 · NSA 1.5 |

<details>
<summary>secrets-in-configmap: 2 affected resources</summary>

- `local-path-storage/ConfigMap/local-path-config`
- `local-path-storage/ConfigMap/local-path-config`

</details>

<details>
<summary>toleration-control-plane: 2 affected resources</summary>

- `local-path-storage/Deployment/local-path-provisioner`
- `local-path-storage/Deployment/local-path-provisioner`

</details>

<details>
<summary>psa-restricted-violations: 3 affected resources</summary>

- `local-path-storage/Deployment/local-path-provisioner (local-path-provisioner)`
- `local-path-storage/Deployment/local-path-provisioner (local-path-provisioner)`
- `local-path-storage/Deployment/local-path-provisioner (local-path-provisioner)`

</details>

<details>
<summary>liveness-readiness-probes: 2 affected resources</summary>

- `local-path-storage/Deployment/local-path-provisioner (local-path-provisioner)`
- `local-path-storage/Deployment/local-path-provisioner (local-path-provisioner)`

</details>

<details>
<summary>Remediation: secrets-in-configmap (2 resources affected)</summary>

## Why This Matters

ConfigMaps are not encrypted at rest and have weaker RBAC defaults than Secrets. Any user with namespace read access can view ConfigMap data, making them an inappropriate store for passwords, tokens, API keys, or private keys.

## How to Fix

Move sensitive values from the ConfigMap into a Secret resource:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-secret
type: Opaque
stringData:
  password: "<managed-externally>"
```

For production workloads, use an external secret manager (Vault, AWS Secrets Manager, GCP Secret Manager) with the External Secrets Operator.

## Learn More

CIS Kubernetes Benchmark 5.4.1 requires secrets to be stored in Secret objects, not ConfigMaps. See the Kubernetes Secrets documentation for proper usage.

**Affected resources:** local-path-storage/ConfigMap/local-path-config, local-path-storage/ConfigMap/local-path-config

</details>

<details>
<summary>Remediation: automount-token (1 resources affected)</summary>

## Why This Matters

When a ServiceAccount token is auto-mounted, every container in the pod can call the Kubernetes API. If a container is compromised through a vulnerability or misconfiguration, the attacker gains API access to enumerate resources, read secrets, or escalate privileges.

## How to Fix

Disable auto-mounting at the pod spec level for workloads that do not need API access:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      automountServiceAccountToken: false
      containers:
        - name: app
          image: my-app:latest
```

For workloads that do require API access, use projected tokens with bounded lifetime and audience restrictions instead of the default long-lived token.

## Learn More

Refer to the Kubernetes documentation on configuring service accounts for pods and CIS Kubernetes Benchmark 5.1.6 for auto-mount token guidance.

**Affected resources:** local-path-storage/Deployment/local-path-provisioner

</details>

<details>
<summary>Remediation: privilege-escalation (1 resources affected)</summary>

## Why This Matters

By default, Kubernetes allows containers to escalate privileges via setuid/setgid binaries, which let a process gain more permissions than its parent. An attacker can exploit this using setuid binaries already present in the container image (like `su`, `sudo`, or `ping`) to elevate from a low-privilege user to root.

## How to Fix

Explicitly disable privilege escalation in the container's securityContext:

```yaml
securityContext:
  allowPrivilegeEscalation: false
  runAsNonRoot: true
  capabilities:
    drop: ["ALL"]
```

This blocks the use of setuid/setgid binaries and prevents the no_new_privs Linux flag from being cleared. The vast majority of application containers do not need privilege escalation.

## Learn More

This is required by the Pod Security Standards "Restricted" profile and CIS Benchmark 5.2.5. Disabling privilege escalation is one of the most impactful single-line security improvements you can make.

**Affected resources:** local-path-storage/Deployment/local-path-provisioner

</details>

<details>
<summary>Remediation: run-as-root (1 resources affected)</summary>

## Why This Matters

Without `runAsNonRoot: true`, Kubernetes does not enforce non-root execution and the container may default to running as UID 0 depending on the image's USER directive. If the image defaults to root, the container process gains full privileges, increasing the blast radius of any compromise or container escape.

## How to Fix

Enforce non-root execution in the securityContext:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
```

With `runAsNonRoot: true`, Kubernetes will reject the pod at admission time if the container image attempts to run as root. Setting an explicit `runAsUser` provides an additional guarantee.

## Learn More

This aligns with CIS Benchmark 5.2.6 and the Pod Security Standards "Restricted" profile. The `runAsNonRoot` field acts as a safety net even when images change their default USER.

**Affected resources:** local-path-storage/Deployment/local-path-provisioner

</details>

<details>
<summary>Remediation: toleration-control-plane (2 resources affected)</summary>

## Why This Matters

Control-plane nodes run critical cluster components like the API server, etcd, and scheduler. If a compromised workload runs on a control-plane node, an attacker can access these components directly, potentially gaining full cluster control or corrupting cluster state.

## How to Fix

Remove the control-plane toleration from your workload spec:

```yaml
spec:
  tolerations:
    # Remove these entries:
    # - key: node-role.kubernetes.io/control-plane
    #   effect: NoSchedule
    # - key: node-role.kubernetes.io/master
    #   effect: NoSchedule
    - key: dedicated
      operator: Equal
      value: my-team
      effect: NoSchedule
```

If the workload genuinely needs to run on control-plane nodes, deploy it in the kube-system namespace with minimal privileges.

## Learn More

The CIS Kubernetes Benchmark recommends isolating control-plane nodes from tenant workloads. See the Kubernetes documentation on taints and tolerations for scheduling best practices.

**Affected resources:** local-path-storage/Deployment/local-path-provisioner, local-path-storage/Deployment/local-path-provisioner

</details>

<details>
<summary>Remediation: network-policy-missing (1 resources affected)</summary>

## Why This Matters

Without NetworkPolicies, every pod in this namespace can communicate freely with every other pod in the cluster. If an attacker compromises a single pod, they can move laterally to databases, internal APIs, and other sensitive services with no network-level barriers.

## How to Fix

Create a default-deny NetworkPolicy for the namespace, then add targeted allow rules for legitimate traffic:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: my-namespace
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
```

After applying the default-deny, create additional NetworkPolicy resources that whitelist only the specific ingress and egress flows your workloads require.

## Learn More

See the Kubernetes documentation on NetworkPolicies and CIS Kubernetes Benchmark 5.3.2. A CNI plugin that supports NetworkPolicy (Calico, Cilium, Weave Net) must be installed for policies to take effect.

**Affected resources:** local-path-storage/Namespace/local-path-storage

</details>

<details>
<summary>Remediation: apparmor-profile (1 resources affected)</summary>

## Why This Matters

AppArmor provides mandatory access control (MAC) that restricts which files, network resources, and capabilities a container process can access. Without an AppArmor profile, the container operates without these restrictions, allowing an attacker with code execution to access any file the container user can read and make unrestricted network connections.

## How to Fix

Apply an AppArmor profile in the container's securityContext (Kubernetes 1.30+):

```yaml
securityContext:
  appArmorProfile:
    type: RuntimeDefault
```

The RuntimeDefault profile provides sensible restrictions for most applications. For tighter control, create a custom Localhost profile that only allows the specific file and network access your application needs.

## Learn More

AppArmor is available on Debian/Ubuntu-based nodes. RHEL/CentOS nodes use SELinux instead. Both provide MAC enforcement. Refer to CIS Benchmark 5.7.5 and the Kubernetes AppArmor documentation.

**Affected resources:** local-path-storage/Deployment/local-path-provisioner

</details>

<details>
<summary>Remediation: capabilities-not-dropped (1 resources affected)</summary>

## Why This Matters

By default, containers receive a set of Linux capabilities including KILL, SETUID, SETGID, and NET_RAW. These defaults are rarely needed by application code and significantly increase the potential damage from a container compromise. Dropping all capabilities follows the principle of least privilege.

## How to Fix

Explicitly drop all capabilities and selectively add back only what your application needs:

```yaml
securityContext:
  capabilities:
    drop: ["ALL"]
    add: ["NET_BIND_SERVICE"]  # Only if needed
```

Most web applications, API servers, and background workers run perfectly with all capabilities dropped. Test your application after making this change to confirm no functionality is lost.

## Learn More

This is required by the Pod Security Standards "Restricted" profile and aligns with CIS Benchmark 5.2.7. Kubernetes best practice is to treat capability grants as exceptions that require explicit justification.

**Affected resources:** local-path-storage/Deployment/local-path-provisioner

</details>

<details>
<summary>Remediation: image-pull-policy (1 resources affected)</summary>

## Why This Matters

When a mutable image tag is used without `imagePullPolicy: Always`, Kubernetes may serve a cached version of the image from the node. If the tag has been updated in the registry (with a security patch or -- worse -- a compromised layer), the running container will not reflect those changes.

## How to Fix

Set `imagePullPolicy: Always` for any container using a mutable tag:

```yaml
containers:
  - name: app
    image: nginx:1.25.3
    imagePullPolicy: Always   # Forces fresh pull each time
```

Alternatively, pin images by digest (`image@sha256:...`), which makes the pull policy irrelevant because the content is immutable.

## Learn More

See the Kubernetes documentation on image pull policies and CIS Kubernetes Benchmark 5.4.2 for pull policy guidance.

**Affected resources:** local-path-storage/Deployment/local-path-provisioner

</details>

<details>
<summary>Remediation: psa-restricted-violations (3 resources affected)</summary>

## Why This Matters

Running as root inside a container means that any container escape vulnerability immediately grants root access on the host node. Even without an escape, root inside the container can modify sensitive files, install packages, and access capabilities that non-root users cannot.

## How to Fix

Set `runAsNonRoot: true` and specify a non-root user ID in the security context:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
```

Set this at the pod level to apply to all containers. Ensure your container image supports running as a non-root user (many official images do).

## Learn More

See the Pod Security Standards Restricted profile and CIS Kubernetes Benchmark 5.2.6. Running as non-root is a fundamental container security best practice.

**Affected resources:** local-path-storage/Deployment/local-path-provisioner, local-path-storage/Deployment/local-path-provisioner, local-path-storage/Deployment/local-path-provisioner

</details>

<details>
<summary>Remediation: read-only-rootfs (1 resources affected)</summary>

## Why This Matters

A writable root filesystem allows an attacker who gains code execution in your container to modify application binaries, install attack tools, plant backdoors, or persist malware across container restarts. Making the filesystem read-only eliminates an entire class of post-exploitation techniques.

## How to Fix

Enable a read-only root filesystem and mount writable volumes only where needed:

```yaml
securityContext:
  readOnlyRootFilesystem: true
volumeMounts:
  - name: tmp
    mountPath: /tmp
volumes:
  - name: tmp
    emptyDir: {}
```

Common paths that need write access include /tmp, /var/cache, and /var/run. Mount each as an emptyDir or tmpfs volume rather than making the entire filesystem writable.

## Learn More

This aligns with CIS Benchmark 5.2.4 and the defense-in-depth principle. Combined with dropping capabilities and running as non-root, a read-only filesystem forms a strong container hardening baseline.

**Affected resources:** local-path-storage/Deployment/local-path-provisioner

</details>

<details>
<summary>Remediation: resource-limits-missing (1 resources affected)</summary>

## Why This Matters

Without resource limits, a single container can consume all available CPU and memory on a node, starving other workloads and triggering cascading failures. An attacker who compromises an unlimited container can mount a denial-of-service attack against the entire node with a simple fork bomb or memory allocation loop.

## How to Fix

Set both CPU and memory limits based on your application's actual resource usage:

```yaml
resources:
  limits:
    cpu: 500m
    memory: 256Mi
  requests:
    cpu: 100m
    memory: 128Mi
```

Profile your application under load to determine appropriate values. Set limits to handle peak usage and requests to match steady-state consumption.

## Learn More

Use LimitRange objects to enforce default limits at the namespace level. Resource limits also determine the pod's QoS class: pods with equal requests and limits get Guaranteed QoS and are last to be evicted.

**Affected resources:** local-path-storage/Deployment/local-path-provisioner

</details>

<details>
<summary>Remediation: resource-requests-missing (1 resources affected)</summary>

## Why This Matters

Resource requests tell the Kubernetes scheduler how much CPU and memory your container needs. Without requests, the scheduler treats the pod as needing zero resources and may pack too many pods onto a single node. This leads to overcommitment, resource contention, throttling, and OOM kills under load.

## How to Fix

Set resource requests based on your application's steady-state usage:

```yaml
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 256Mi
```

Observe your application's actual resource consumption using `kubectl top` or a monitoring tool, then set requests to match the typical steady-state usage.

## Learn More

Resource requests determine the pod's QoS class and scheduling behavior. Pods with requests equal to limits receive Guaranteed QoS. Use Vertical Pod Autoscaler (VPA) to automatically recommend request values.

**Affected resources:** local-path-storage/Deployment/local-path-provisioner

</details>

<details>
<summary>Remediation: run-as-group (1 resources affected)</summary>

## Why This Matters

Without an explicit runAsGroup, the container process defaults to GID 0 (the root group). Files and sockets owned by the root group become accessible to the container, including potentially sensitive host files if volumes are mounted. This widens the attack surface unnecessarily.

## How to Fix

Set an explicit non-root group in the securityContext:

```yaml
securityContext:
  runAsGroup: 1000
  runAsUser: 1000
  runAsNonRoot: true
```

Ensure the container image's application files and directories are readable by the specified GID. You may need to adjust file ownership in your Dockerfile with `chown`.

## Learn More

This aligns with CIS Benchmark 5.2.6 and the Pod Security Standards "Restricted" profile. Always set runAsUser, runAsGroup, and runAsNonRoot together for comprehensive identity control.

**Affected resources:** local-path-storage/Deployment/local-path-provisioner

</details>

<details>
<summary>Remediation: seccomp-profile (1 resources affected)</summary>

## Why This Matters

Without a Seccomp profile, containers can invoke any of the 300+ Linux system calls, leaving the entire kernel attack surface exposed. Kernel vulnerabilities in obscure syscalls are a primary vector for container escapes. Seccomp filtering blocks dangerous syscalls that legitimate applications never use.

## How to Fix

Apply a Seccomp profile at the container or pod level:

```yaml
securityContext:
  seccompProfile:
    type: RuntimeDefault
```

The RuntimeDefault profile blocks approximately 50 dangerous syscalls while allowing normal application behavior. For stricter controls, use a custom Localhost profile tailored to your application's needs. Set the profile at the pod level to apply it to all containers.

## Learn More

Seccomp profiles are required by the Pod Security Standards "Restricted" profile and CIS Benchmark 5.7.2. Use tools like `strace` or the Security Profiles Operator to generate custom profiles for your workloads.

**Affected resources:** local-path-storage/Deployment/local-path-provisioner

</details>

<details>
<summary>Remediation: token-projection-config (1 resources affected)</summary>

## Why This Matters

Without explicit projection configuration, ServiceAccount tokens use Kubernetes defaults: no audience restriction and a long expiration. A stolen token remains valid for an extended period and can be used against any API server endpoint, widening the blast radius of a compromise.

## How to Fix

Add a projected volume with explicit expiration and audience:

```yaml
spec:
  volumes:
    - name: token
      projected:
        sources:
          - serviceAccountToken:
              expirationSeconds: 3600
              audience: my-api
              path: token
  containers:
    - name: app
      volumeMounts:
        - name: token
          mountPath: /var/run/secrets/tokens
          readOnly: true
```

Projected tokens auto-rotate before expiry and are rejected by endpoints outside the specified audience.

## Learn More

See the Kubernetes documentation on projected volumes and service account token volume projection for detailed configuration options.

**Affected resources:** local-path-storage/Deployment/local-path-provisioner

</details>

<details>
<summary>Remediation: network-policy-egress-unrestricted (1 resources affected)</summary>

## Why This Matters

Without any egress NetworkPolicy in this namespace, pods can freely send traffic to any destination including the public internet. A compromised pod can exfiltrate sensitive data, reach cloud metadata services (e.g., 169.254.169.254), or establish reverse shells to attacker-controlled servers.

## How to Fix

Create a NetworkPolicy with `Egress` in `policyTypes` to restrict outbound traffic. At minimum, allow DNS resolution:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-egress
  namespace: my-namespace
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector: {}
      ports:
        - port: 53
          protocol: UDP
```

Add additional egress rules for specific services your workloads need to reach.

## Learn More

See the Kubernetes NetworkPolicy documentation and CIS Kubernetes Benchmark 5.3.2. Egress controls are a key defense-in-depth measure recommended by the NSA/CISA Kubernetes Hardening Guide.

**Affected resources:** local-path-storage/Namespace/local-path-storage

</details>

<details>
<summary>Remediation: psa-labels-missing (1 resources affected)</summary>

## Why This Matters

Without PSA enforcement labels, any pod configuration is allowed in this namespace, including privileged containers, host namespace access, and root execution. This bypasses Kubernetes' built-in Pod Security Standards and leaves the namespace vulnerable to workloads that could compromise the node.

## How to Fix

Add Pod Security Admission labels to enforce a security profile on all pods in the namespace:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: local-path-storage
  labels:
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

Start with `baseline` enforcement to block known privilege escalations, then upgrade to `restricted` after verifying all workloads are compliant.

## Learn More

See the Kubernetes Pod Security Admission documentation and CIS Kubernetes Benchmark 5.2. The three-tier approach (enforce, audit, warn) allows gradual adoption of stricter profiles.

**Affected resources:** local-path-storage/Namespace/local-path-storage

</details>

<details>
<summary>Remediation: ephemeral-storage-limits (1 resources affected)</summary>

## Why This Matters

Ephemeral storage includes container logs, emptyDir volumes, and the writable container layer. Without limits, a single container can fill the node's root disk, triggering eviction of all pods on that node and potentially causing a cascading failure across your cluster. This is a common denial-of-service vector.

## How to Fix

Set ephemeral-storage limits alongside your CPU and memory limits:

```yaml
resources:
  limits:
    ephemeral-storage: 1Gi
  requests:
    ephemeral-storage: 500Mi
```

Estimate your application's disk usage from logs, temporary files, and cache data. If your application writes large temporary files, consider using a PersistentVolumeClaim instead of ephemeral storage.

## Learn More

The kubelet evicts pods that exceed their ephemeral-storage limit. Use LimitRange to set default ephemeral-storage limits at the namespace level to catch containers that omit this setting.

**Affected resources:** local-path-storage/Deployment/local-path-provisioner

</details>

<details>
<summary>Remediation: image-no-digest (1 resources affected)</summary>

## Why This Matters

Image tags are mutable pointers -- a registry administrator or attacker can re-push a different image under the same tag. Without a digest, you have no cryptographic guarantee that the image you deploy is the one you tested.

## How to Fix

Pin images by their SHA-256 content digest for a fully immutable reference:

```yaml
containers:
  - name: app
    image: nginx@sha256:a8281ce420348a01ea6e   # Immutable
```

Use `crane digest nginx:1.25.3` or `skopeo inspect` to resolve a tag to its digest during CI/CD, then commit the pinned reference.

## Learn More

SLSA Level 1+ and NIST SP 800-190 recommend digest pinning for container supply chain integrity. See the Kubernetes images documentation for details.

**Affected resources:** local-path-storage/Deployment/local-path-provisioner

</details>

<details>
<summary>Remediation: liveness-readiness-probes (2 resources affected)</summary>

## Why This Matters

Without a liveness probe, Kubernetes cannot detect when a container has become unresponsive or deadlocked. The container continues running and consuming resources while failing to serve traffic. Users experience timeouts and errors until someone manually intervenes.

## How to Fix

Add a liveness probe that checks the container's health:

```yaml
containers:
  - name: app
    livenessProbe:
      httpGet:
        path: /healthz
        port: 8080
      initialDelaySeconds: 15
      periodSeconds: 10
      failureThreshold: 3
```

Use `httpGet` for HTTP services, `tcpSocket` for TCP services, or `exec` with a custom health check script for non-network workloads.

## Learn More

See the Kubernetes documentation on container probes. Set initialDelaySeconds high enough for your application to start, and consider adding a startupProbe for slow-starting containers.

**Affected resources:** local-path-storage/Deployment/local-path-provisioner, local-path-storage/Deployment/local-path-provisioner

</details>

<details>
<summary>Remediation: priority-class-missing (1 resources affected)</summary>

## Why This Matters

Without a PriorityClass, pods receive default priority (typically 0) and are among the first to be evicted during resource pressure or node maintenance. This means important application workloads may be killed before less critical ones, leading to unpredictable outages.

## How to Fix

Define PriorityClasses for your workloads and assign them appropriately:

```yaml
apiVersion: scheduling.k8s.io/v1
kind: PriorityClass
metadata:
  name: app-medium
value: 100000
---
# Reference in your workload:
spec:
  priorityClassName: app-medium
```

Create a tiered priority scheme (e.g., app-critical: 500000, app-medium: 100000, app-low: 10000) that reflects your workload importance hierarchy.

## Learn More

Refer to the Kubernetes Pod Priority and Preemption documentation. Establishing a consistent priority scheme across namespaces ensures predictable eviction behavior during resource contention.

**Affected resources:** local-path-storage/Deployment/local-path-provisioner

</details>

<details>
<summary>Remediation: runtime-class (1 resources affected)</summary>

## Why This Matters

Without a RuntimeClass, pods use the default container runtime (typically runc), which shares the host kernel directly with containers. A kernel vulnerability can allow container escape to the host. Sandboxed runtimes like gVisor or Kata Containers add an additional isolation layer that intercepts system calls or runs containers in lightweight VMs.

## How to Fix

Specify a sandboxed RuntimeClass in the pod spec:

```yaml
spec:
  runtimeClassName: gvisor
```

Available RuntimeClasses depend on your cluster configuration. Common options include `gvisor` (user-space kernel), `kata` (micro-VMs), and `firecracker`. Check your cluster's available RuntimeClasses with `kubectl get runtimeclasses`.

## Learn More

Sandboxed runtimes are especially important for multi-tenant clusters and workloads processing untrusted input. They add latency overhead, so evaluate performance requirements. See the Kubernetes RuntimeClass documentation.

**Affected resources:** local-path-storage/Deployment/local-path-provisioner

</details>

<details>
<summary>Remediation: topology-spread (1 resources affected)</summary>

## Why This Matters

Without topology spread constraints, the scheduler may place all replicas on the same node or in the same availability zone. If that node or zone fails, your entire service goes down despite having multiple replicas. This negates the high-availability benefits of running multiple pods.

## How to Fix

Add topology spread constraints to distribute replicas across failure domains:

```yaml
spec:
  topologySpreadConstraints:
    - maxSkew: 1
      topologyKey: kubernetes.io/hostname
      whenUnsatisfiable: DoNotSchedule
      labelSelector:
        matchLabels:
          app: my-app
    - maxSkew: 1
      topologyKey: topology.kubernetes.io/zone
      whenUnsatisfiable: ScheduleAnyway
```

Use `kubernetes.io/hostname` for node-level spreading and `topology.kubernetes.io/zone` for zone-level spreading.

## Learn More

See the Kubernetes Pod Topology Spread Constraints documentation. Combining hostname and zone constraints provides both node-level and zone-level fault tolerance.

**Affected resources:** local-path-storage/Deployment/local-path-provisioner

</details>

<details>
<summary>Remediation: limit-range-missing (1 resources affected)</summary>

## Why This Matters

Without a LimitRange, any container can be created without resource constraints. A single runaway or malicious pod can consume all node CPU and memory, causing denial of service for other workloads on the same node.

## How to Fix

Create a LimitRange in the namespace to set default and maximum resource constraints:

```yaml
apiVersion: v1
kind: LimitRange
metadata:
  name: default-limits
  namespace: my-app
spec:
  limits:
    - type: Container
      default:
        cpu: 500m
        memory: 256Mi
      defaultRequest:
        cpu: 100m
        memory: 128Mi
      max:
        cpu: "2"
        memory: 1Gi
```

Containers that omit resource requests/limits will inherit these defaults automatically.

## Learn More

CIS Kubernetes Benchmark 5.2.1 recommends LimitRanges for resource governance. See https://kubernetes.io/docs/concepts/policy/limit-range/ for configuration details.

**Affected resources:** local-path-storage/Namespace/local-path-storage

</details>

<details>
<summary>Remediation: resource-quota-missing (1 resources affected)</summary>

## Why This Matters

Without a ResourceQuota, a single namespace can consume the entire cluster's CPU, memory, and storage. This creates a noisy-neighbor problem where one team's workloads starve others, and makes capacity planning impossible.

## How to Fix

Create a ResourceQuota to cap the namespace's total resource consumption:

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: compute-quota
  namespace: my-app
spec:
  hard:
    requests.cpu: "10"
    requests.memory: 20Gi
    limits.cpu: "20"
    limits.memory: 40Gi
    pods: "50"
    services: "10"
```

Tune quota values based on the namespace's actual workload requirements and cluster capacity.

## Learn More

CIS Kubernetes Benchmark 5.2.2 recommends ResourceQuotas for multi-tenant clusters. See https://kubernetes.io/docs/concepts/policy/resource-quotas/ for quota configuration and enforcement behavior.

**Affected resources:** local-path-storage/Namespace/local-path-storage

</details>

## Cluster-Scoped Resources

### Cluster-Scoped (45 findings — 🔴25 🟠13 🟡5 🔵1 ⬜1)

| Severity | Check | Resources | Message | Frameworks |
|----------|-------|-----------|---------|-----------|
| 🔴 Critical | rbac-escalation-verbs | **4 resources** | ClusterRole "admin" grants escalation verb "impersonate", allowing RBAC privilege escalation. | CIS 5.1.1 · CIS 5.1.8 · MITRE T1078 · MITRE T1068 · NSA 3.1 |
| 🔴 Critical | rbac-cluster-admin | **3 resources** | ClusterRoleBinding "cluster-admin" grants cluster-admin privileges. Every cluster-admin binding should be justified and documented. | CIS 5.1.1 · MITRE T1078 · NSA 3.1 |
| 🔴 Critical | rbac-wildcard-apigroups | **8 resources** | ClusterRole "cluster-admin" grants access to wildcard (*) API groups, allowing operations across all API groups. | CIS 5.1.3 · MITRE T1078 · NSA 3.1 |
| 🔴 Critical | rbac-wildcard-resources | **7 resources** | ClusterRole "cluster-admin" grants access to wildcard (*) resources, allowing operations on all resource types. | CIS 5.1.3 · MITRE T1078 · NSA 3.1 |
| 🔴 Critical | rbac-wildcard-verbs | **2 resources** | ClusterRole "cluster-admin" grants wildcard (*) verbs, violating least-privilege principle. | CIS 5.1.1 · CIS 5.1.3 · MITRE T1078 · NSA 3.1 |
| 🔴 Critical | secrets-unencrypted | Cluster/etcd | Cluster etcd encryption at rest could not be verified. Ensure EncryptionConfiguration is enabled for Secret resources. | CIS 1.2.28 · CIS 1.2.29 · MITRE T1552 · NSA 5.1 · NSA 5.2 |
| 🟠 High | rbac-exec-access | **3 resources** | ClusterRole "admin" grants exec/attach access to pods, equivalent to SSH access. | CIS 5.1.1 · MITRE T1609 · NSA 3.1 |
| 🟠 High | rbac-secret-access | **5 resources** | ClusterRole "admin" grants read access to Secrets, which may contain credentials and TLS keys. | CIS 5.1.2 · MITRE T1552 · NSA 3.1 · NSA 5.1 |
| 🟠 High | rbac-group-bindings | **5 resources** | ClusterRoleBinding "kv-e2e-group-binding-authenticated" binds to overly broad group "system:authenticated", potentially granting permissions to all users. | CIS 5.1.7 · CIS 5.1.1 · MITRE T1078 · NSA 3.1 |
| 🟡 Medium | rbac-log-access | **5 resources** | ClusterRole "admin" grants access to pod logs, which may contain sensitive application data. | CIS 5.1.1 · MITRE T1530 · NSA 3.1 |
| 🔵 Low | rbac-subject-external | ClusterRoleBinding/kv-e2e-external-user-binding | ClusterRoleBinding "kv-e2e-external-user-binding" references external user "contractor@external-corp.com". External user bindings may become stale. | CIS 5.1.1 · MITRE T1078 · NSA 3.1 |
| ⬜ Info | rbac-unused-roles | ClusterRole/admin | ClusterRole "admin" has no bindings and may be unused. | CIS 5.1.1 · MITRE T1078 · NSA 3.1 |

<details>
<summary>rbac-escalation-verbs: 4 affected resources</summary>

- `ClusterRole/admin`
- `ClusterRole/edit`
- `ClusterRole/system:aggregate-to-edit`
- `ClusterRole/system:controller:clusterrole-aggregation-controller`

</details>

<details>
<summary>rbac-cluster-admin: 3 affected resources</summary>

- `ClusterRoleBinding/cluster-admin`
- `ClusterRoleBinding/kubeadm:cluster-admins`
- `ClusterRoleBinding/kv-e2e-cluster-admin-binding`

</details>

<details>
<summary>rbac-wildcard-apigroups: 8 affected resources</summary>

- `ClusterRole/cluster-admin`
- `ClusterRole/kv-e2e-wildcard-apigroups`
- `ClusterRole/system:controller:disruption-controller`
- `ClusterRole/system:controller:generic-garbage-collector`
- `ClusterRole/system:controller:horizontal-pod-autoscaler`
- `ClusterRole/system:controller:namespace-controller`
- `ClusterRole/system:controller:resourcequota-controller`
- `ClusterRole/system:kube-controller-manager`

</details>

<details>
<summary>rbac-wildcard-resources: 7 affected resources</summary>

- `ClusterRole/cluster-admin`
- `ClusterRole/kv-e2e-wildcard-resources`
- `ClusterRole/system:controller:generic-garbage-collector`
- `ClusterRole/system:controller:horizontal-pod-autoscaler`
- `ClusterRole/system:controller:namespace-controller`
- `ClusterRole/system:controller:resourcequota-controller`
- `ClusterRole/system:kube-controller-manager`

</details>

<details>
<summary>rbac-wildcard-verbs: 2 affected resources</summary>

- `ClusterRole/cluster-admin`
- `ClusterRole/system:kubelet-api-admin`

</details>

<details>
<summary>rbac-exec-access: 3 affected resources</summary>

- `ClusterRole/admin`
- `ClusterRole/edit`
- `ClusterRole/system:aggregate-to-edit`

</details>

<details>
<summary>rbac-secret-access: 5 affected resources</summary>

- `ClusterRole/admin`
- `ClusterRole/edit`
- `ClusterRole/system:aggregate-to-edit`
- `ClusterRole/system:kube-controller-manager`
- `ClusterRole/system:node`

</details>

<details>
<summary>rbac-group-bindings: 5 affected resources</summary>

- `ClusterRoleBinding/kv-e2e-group-binding-authenticated`
- `ClusterRoleBinding/kv-e2e-group-binding-unauthenticated`
- `ClusterRoleBinding/system:basic-user`
- `ClusterRoleBinding/system:discovery`
- `ClusterRoleBinding/system:public-info-viewer`

</details>

<details>
<summary>rbac-log-access: 5 affected resources</summary>

- `ClusterRole/admin`
- `ClusterRole/edit`
- `ClusterRole/local-path-provisioner-role`
- `ClusterRole/system:aggregate-to-view`
- `ClusterRole/view`

</details>

<details>
<summary>Remediation: rbac-escalation-verbs (4 resources affected)</summary>

## Why This Matters

The `bind`, `escalate`, and `impersonate` verbs are special RBAC verbs that allow bypassing normal privilege restrictions. `bind` lets a user assign roles they do not hold, `escalate` lets a user grant permissions beyond their own, and `impersonate` lets a user act as another identity. Any of these can lead to full cluster compromise.

## How to Fix

Remove escalation verbs and replace with specific non-escalating verbs:

```yaml
rules:
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["roles", "rolebindings"]
    verbs: ["get", "list", "watch"]  # Read-only, no bind/escalate
```

Only cluster administrators and RBAC management controllers (e.g., the Kubernetes controller manager) should hold these verbs.

## Learn More

See CIS Kubernetes Benchmark 5.1.8 on privilege escalation prevention and the Kubernetes RBAC documentation section on escalation prevention restrictions.

**Affected resources:** ClusterRole/admin, ClusterRole/edit, ClusterRole/system:aggregate-to-edit, ClusterRole/system:controller:clusterrole-aggregation-controller

</details>

<details>
<summary>Remediation: rbac-cluster-admin (3 resources affected)</summary>

## Why This Matters

The `cluster-admin` ClusterRole grants unrestricted access to every resource in every namespace, including the ability to create and modify RBAC rules themselves. A compromised identity with cluster-admin privileges has full control of the entire cluster, making this the highest-value target for attackers.

## How to Fix

Replace cluster-admin bindings with purpose-built ClusterRoles scoped to actual needs:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: my-admin
roleRef:
  kind: ClusterRole
  name: my-limited-admin-role    # Scoped permissions
  apiGroup: rbac.authorization.k8s.io
subjects:
  - kind: User
    name: admin@example.com
    apiGroup: rbac.authorization.k8s.io
```

Conduct periodic access reviews to ensure cluster-admin bindings remain justified and documented.

## Learn More

See CIS Kubernetes Benchmark 5.1.1 on limiting cluster-admin usage and the NSA/CISA Kubernetes Hardening Guide on minimizing administrative privileges.

**Affected resources:** ClusterRoleBinding/cluster-admin, ClusterRoleBinding/kubeadm:cluster-admins, ClusterRoleBinding/kv-e2e-cluster-admin-binding

</details>

<details>
<summary>Remediation: rbac-wildcard-apigroups (8 resources affected)</summary>

## Why This Matters

A wildcard API group (`*`) grants access across every API group in the cluster, including custom resource definitions and any API groups added in the future. This means an attacker inheriting this role can operate on resources the original author never anticipated.

## How to Fix

Replace the wildcard with the specific API groups your workload requires:

```yaml
rules:
  - apiGroups: [""]            # Core API (pods, services, secrets)
    resources: ["pods"]
    verbs: ["get", "list"]
  - apiGroups: ["apps"]         # Apps API (deployments, statefulsets)
    resources: ["deployments"]
    verbs: ["get", "list"]
```

Common API groups: `""` (core), `"apps"`, `"batch"`, `"networking.k8s.io"`, `"rbac.authorization.k8s.io"`.

## Learn More

See CIS Kubernetes Benchmark 5.1.3 and the Kubernetes API groups documentation for a complete list of built-in API groups and their resources.

**Affected resources:** ClusterRole/cluster-admin, ClusterRole/kv-e2e-wildcard-apigroups, ClusterRole/system:controller:disruption-controller, ClusterRole/system:controller:generic-garbage-collector, ClusterRole/system:controller:horizontal-pod-autoscaler, ClusterRole/system:controller:namespace-controller, ClusterRole/system:controller:resourcequota-controller, ClusterRole/system:kube-controller-manager

</details>

<details>
<summary>Remediation: rbac-wildcard-resources (7 resources affected)</summary>

## Why This Matters

A wildcard resource (`*`) grants access to every resource type in the specified API group, including Secrets, ConfigMaps, and any future resource types added to the cluster. This far exceeds what any single workload needs and creates a significant blast radius if compromised.

## How to Fix

Enumerate the specific resources your application accesses and restrict the rule:

```yaml
rules:
  - apiGroups: [""]
    resources: ["pods", "services", "configmaps"]
    verbs: ["get", "list", "watch"]
```

Use `kubectl auth can-i --list --as=system:serviceaccount:ns:sa` to audit the effective permissions of each service account before and after changes.

## Learn More

See CIS Kubernetes Benchmark 5.1.3 on least-privilege RBAC and the Kubernetes RBAC documentation on role aggregation for managing permissions at scale.

**Affected resources:** ClusterRole/cluster-admin, ClusterRole/kv-e2e-wildcard-resources, ClusterRole/system:controller:generic-garbage-collector, ClusterRole/system:controller:horizontal-pod-autoscaler, ClusterRole/system:controller:namespace-controller, ClusterRole/system:controller:resourcequota-controller, ClusterRole/system:kube-controller-manager

</details>

<details>
<summary>Remediation: rbac-wildcard-verbs (2 resources affected)</summary>

## Why This Matters

A wildcard verb (`*`) grants every possible action on the specified resources, including delete, patch, and create. An attacker who assumes this role can modify or destroy resources, exfiltrate data, or escalate privileges far beyond what the workload actually requires.

## How to Fix

Replace the wildcard with the specific verbs your application needs:

```yaml
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "watch"]  # Only read access
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["get", "update"]          # Read + update only
```

Enable Kubernetes audit logging and review the audit trail to identify which verbs are actually used before tightening permissions.

## Learn More

Refer to CIS Kubernetes Benchmark 5.1.3 and the Kubernetes RBAC documentation for guidance on applying the principle of least privilege to role definitions.

**Affected resources:** ClusterRole/cluster-admin, ClusterRole/system:kubelet-api-admin

</details>

<details>
<summary>Remediation: secrets-unencrypted (1 resources affected)</summary>

## Why This Matters

By default, Kubernetes stores Secrets as base64-encoded plaintext in etcd. Anyone with direct etcd access or an etcd backup can read every secret in the cluster, including database passwords, API keys, and TLS private keys.

## How to Fix

Configure encryption at rest via the API server EncryptionConfiguration:

```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources: [secrets]
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: <base64-encoded-key>
      - identity: {}
```

For managed clusters (EKS, GKE, AKS), enable the cloud-native KMS envelope encryption option. For self-managed clusters, use a KMS provider or the secretbox provider for local encryption.

## Learn More

CIS Kubernetes Benchmark 1.2.29 requires encryption at rest for etcd. See the Kubernetes encrypting data at rest documentation for setup details.

**Affected resources:** Cluster/etcd

</details>

<details>
<summary>Remediation: rbac-exec-access (3 resources affected)</summary>

## Why This Matters

The `pods/exec` and `pods/attach` sub-resources grant the ability to run arbitrary commands inside running containers, which is functionally equivalent to SSH access. An attacker with exec access can read environment variables, access mounted secrets, install tools, and pivot to other systems on the network.

## How to Fix

Remove exec and attach sub-resources from the role rules:

```yaml
rules:
  - apiGroups: [""]
    resources: ["pods"]              # pods only, no sub-resources
    verbs: ["get", "list", "watch"]
  # Do NOT include:
  # resources: ["pods/exec", "pods/attach"]
```

If exec access is required for debugging, restrict it to specific namespaces and enable Kubernetes audit logging to monitor all exec sessions in production.

## Learn More

See CIS Kubernetes Benchmark 5.1.3 and MITRE ATT&CK technique T1609 (Container Administration Command) for the exec-based attack vector.

**Affected resources:** ClusterRole/admin, ClusterRole/edit, ClusterRole/system:aggregate-to-edit

</details>

<details>
<summary>Remediation: rbac-secret-access (5 resources affected)</summary>

## Why This Matters

Roles granting read access to Secrets expose every credential in the namespace, including database passwords, TLS private keys, API tokens, and third-party credentials. A compromised workload with this access can exfiltrate all secrets and pivot to external systems.

## How to Fix

Restrict access to only the specific secrets your workload needs using `resourceNames`:

```yaml
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["my-app-tls", "my-app-db-creds"]
    verbs: ["get"]
```

For sensitive credentials, consider using an external secrets manager (HashiCorp Vault, AWS Secrets Manager, or GCP Secret Manager) with the External Secrets Operator.

## Learn More

See CIS Kubernetes Benchmark 5.1.2 on minimizing access to secrets and MITRE ATT&CK technique T1552 (Unsecured Credentials) for the threat model.

**Affected resources:** ClusterRole/admin, ClusterRole/edit, ClusterRole/system:aggregate-to-edit, ClusterRole/system:kube-controller-manager, ClusterRole/system:node

</details>

<details>
<summary>Remediation: rbac-group-bindings (5 resources affected)</summary>

## Why This Matters

Groups like `system:authenticated` include every authenticated identity in the cluster, including all service accounts across all namespaces. Binding permissions to these groups effectively grants those permissions to every pod, user, and controller in the cluster. `system:unauthenticated` and `system:anonymous` are even more dangerous as they grant access without any authentication.

## How to Fix

Replace broad group bindings with specific subjects:

```yaml
subjects:
  - kind: Group
    name: dev-team                    # Specific group
    apiGroup: rbac.authorization.k8s.io
  - kind: ServiceAccount
    name: my-app
    namespace: production             # Specific service account
```

Never bind roles to `system:authenticated`, `system:unauthenticated`, or `system:anonymous` unless you explicitly intend to grant permissions cluster-wide.

## Learn More

See CIS Kubernetes Benchmark 5.1.5 and the NSA/CISA Kubernetes Hardening Guide on restricting broad group-based access.

**Affected resources:** ClusterRoleBinding/kv-e2e-group-binding-authenticated, ClusterRoleBinding/kv-e2e-group-binding-unauthenticated, ClusterRoleBinding/system:basic-user, ClusterRoleBinding/system:discovery, ClusterRoleBinding/system:public-info-viewer

</details>

<details>
<summary>Remediation: rbac-log-access (5 resources affected)</summary>

## Why This Matters

The `pods/log` sub-resource provides access to container stdout/stderr output. Applications frequently log sensitive data inadvertently, including authentication tokens, database connection strings, API keys, and personally identifiable information (PII). An attacker with log access can harvest these credentials without needing exec access.

## How to Fix

Remove the `pods/log` sub-resource and grant log access only to dedicated monitoring roles:

```yaml
rules:
  - apiGroups: [""]
    resources: ["pods"]              # pods only, no sub-resources
    verbs: ["get", "list", "watch"]
  # Grant pods/log only to monitoring-specific roles
```

Additionally, configure applications to avoid logging sensitive data. Use structured logging libraries that support field redaction.

## Learn More

See MITRE ATT&CK technique T1530 (Data from Cloud Storage) and the Kubernetes RBAC documentation on sub-resource access control.

**Affected resources:** ClusterRole/admin, ClusterRole/edit, ClusterRole/local-path-provisioner-role, ClusterRole/system:aggregate-to-view, ClusterRole/view

</details>

<details>
<summary>Remediation: rbac-subject-external (1 resources affected)</summary>

## Why This Matters

Individual User subjects in RBAC bindings reference external identities (e.g., from an OIDC provider or client certificates). When users leave the organization or change roles, these bindings become orphaned, granting access to identities that should no longer have it. Unlike groups, user bindings cannot be centrally managed through an identity provider.

## How to Fix

Replace individual User subjects with Group subjects managed by your identity provider:

```yaml
subjects:
  - kind: Group
    name: platform-engineers          # Managed by IdP
    apiGroup: rbac.authorization.k8s.io
  # Avoid:
  # - kind: User
  #   name: jane@example.com
```

If individual user bindings are necessary, implement an automated process to reconcile RBAC bindings against your identity provider directory.

## Learn More

See the Kubernetes authentication documentation on OIDC integration and CIS Kubernetes Benchmark section 5.1 for RBAC best practices on subject management.

**Affected resources:** ClusterRoleBinding/kv-e2e-external-user-binding

</details>

<details>
<summary>Remediation: rbac-unused-roles (1 resources affected)</summary>

## Why This Matters

Unused Roles and ClusterRoles are dormant permissions waiting to be activated. An attacker who can create or modify RoleBindings could bind these unused roles to gain additional privileges. They also create confusion during audits and make it harder to understand the actual RBAC posture.

## How to Fix

Verify the role is truly unused, then remove it:

```bash
# Check for any bindings referencing this role
kubectl get rolebindings,clusterrolebindings -A \
  -o json | jq '.items[] | select(.roleRef.name=="unused-role")'

# Remove the unused role
kubectl delete clusterrole unused-role
kubectl delete role unused-role -n my-namespace
```

Implement a regular RBAC hygiene process to review and clean up unused roles quarterly.

## Learn More

See the Kubernetes RBAC best practices documentation and CIS Kubernetes Benchmark section 5.1 for guidance on maintaining a clean RBAC configuration.

**Affected resources:** ClusterRole/admin

</details>

