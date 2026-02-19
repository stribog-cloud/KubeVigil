# KubeVigil E2E -- Expected Findings per Scenario

This document records the checks that should trigger, expected minimum finding
counts, severity distribution, and pass criteria for every E2E scenario
directory under `test/e2e/scenarios/`.

Use this as a reference when writing automated assertions or when manually
verifying scan output.

---

## workload-security

**Namespace:** `kv-e2e-workload`
**Manifest files:** 11 (namespace.yaml + 10 workload manifests)

### Checks that should trigger

| Check ID | Severity | Source File | Triggering Resource(s) |
|----------|----------|-------------|------------------------|
| `privileged` | Critical | privileged.yaml | Deployment `privileged-container` -- container `privileged-app` has `privileged: true` |
| `capabilities-added` | High | capabilities.yaml | Deployment `dangerous-capabilities` -- containers `caps-sys-admin` (SYS_ADMIN, NET_RAW), `caps-ptrace` (SYS_PTRACE, DAC_OVERRIDE) |
| `capabilities-not-dropped` | Medium | capabilities.yaml | Deployment `dangerous-capabilities` -- all 3 containers lack `drop: ["ALL"]` |
| `host-pid` | Critical | host-namespaces.yaml | Pod `host-pid-pod` -- `hostPID: true` |
| `host-ipc` | Critical | host-namespaces.yaml | Pod `host-ipc-pod` -- `hostIPC: true` |
| `host-network` | Critical | host-namespaces.yaml | Pod `host-network-pod` -- `hostNetwork: true` |
| `host-path-volumes` | Critical | host-path-volumes.yaml | Pods `hostpath-root` (/), `hostpath-etc` (/etc), `hostpath-docker-sock` (/var/run/docker.sock) |
| `host-path-volumes` | High | host-path-volumes.yaml | Pod `hostpath-var-log` (/var/log) |
| `host-path-volumes` | Medium | host-path-volumes.yaml | Pod `hostpath-opt-data` (/opt/data) |
| `host-ports` | High | host-ports.yaml | Pod `host-port-pod` -- container binds hostPort 8080 |
| `run-as-root` | High | run-as-root.yaml | Pods `explicit-root` (UID 0), `missing-non-root` (no runAsNonRoot) |
| `run-as-high-uid` | Low | run-as-root.yaml | Pod `low-uid-pod` -- UID 1000 is below the 10000 threshold |
| `run-as-group` | Medium | run-as-root.yaml | Pods `explicit-root` (GID 0), `missing-non-root` (no runAsGroup), `low-uid-pod` (no runAsGroup) |
| `read-only-rootfs` | Medium | read-only-rootfs.yaml | Deployment `writable-rootfs` -- both containers lack `readOnlyRootFilesystem: true` |
| `resource-limits-missing` | Medium | resource-limits.yaml | Deployment `resource-issues` -- containers `no-resources`, `requests-no-limits` |
| `resource-requests-missing` | Medium | resource-limits.yaml | Deployment `resource-issues` -- containers `no-resources`, `limits-no-requests` |
| `resource-limits-ratio` | Low | resource-limits.yaml | Deployment `resource-issues` -- container `extreme-ratio` (CPU 10x, memory ~16x) |
| `ephemeral-storage-limits` | Low | resource-limits.yaml | Deployment `resource-issues` -- all 4 containers lack ephemeral-storage limits |
| `proc-mount` | High | proc-mount.yaml | Pod `unmasked-proc` -- `procMount: Unmasked` |
| `seccomp-profile` | Medium | seccomp-apparmor.yaml | Deployment `missing-profiles` -- container `no-seccomp-no-apparmor` (no seccomp) |
| `apparmor-profile` | Medium | seccomp-apparmor.yaml | Deployment `missing-profiles` -- both containers lack `appArmorProfile` |

### Expected minimum finding count

**35+ findings**

### Severity distribution

| Severity | Minimum Count |
|----------|---------------|
| Critical | 7 (privileged, host-pid, host-ipc, host-network, 3x host-path-volumes Critical) |
| High | 7 (capabilities-added x2, host-ports, run-as-root x2, host-path-volumes High, proc-mount) |
| Medium | 15+ (capabilities-not-dropped, run-as-group, read-only-rootfs, resource-limits, resource-requests, seccomp, apparmor, etc.) |
| Low | 6+ (run-as-high-uid, resource-limits-ratio, ephemeral-storage-limits x4, host-path-volumes Medium) |

### Pass criteria

- Every check ID listed above appears at least once in the scan output.
- Exit code is `1` (findings present).
- Zero false positives on the `namespace.yaml` file itself (it is just a Namespace).
- The `privileged` finding references Deployment `privileged-container`.
- Host namespace findings reference distinct Pods (host-pid-pod, host-ipc-pod, host-network-pod).

---

## image-security

**Namespace:** `kv-e2e-image`
**Manifest files:** 6 (namespace.yaml + 5 image manifests)

### Checks that should trigger

| Check ID | Severity | Source File | Triggering Resource(s) |
|----------|----------|-------------|------------------------|
| `image-tag-latest` | Medium | latest-tag.yaml | Deployment `latest-tag-demo` -- containers `explicit-latest` (nginx:latest), `implicit-latest` (busybox, no tag) |
| `image-tag-latest` | Medium | mixed-images.yaml | Deployment `mixed-images-demo` -- `init-no-tag` (busybox), `sidecar-latest` (busybox:latest) |
| `image-tag-latest` | Medium | pull-policy.yaml | Deployment `pull-policy-demo` -- container `latest-default` (nginx:latest) |
| `image-tag-missing` | Medium | latest-tag.yaml | Deployment `latest-tag-demo` -- container `implicit-latest` (busybox, no tag, no digest) |
| `image-tag-missing` | Medium | mixed-images.yaml | Deployment `mixed-images-demo` -- `init-no-tag` (busybox, no tag) |
| `image-no-digest` | Low | latest-tag.yaml | Deployment `latest-tag-demo` -- both containers (no @sha256:...) |
| `image-no-digest` | Low | no-digest.yaml | Deployment `no-digest-demo` -- both containers (no digest) |
| `image-no-digest` | Low | mixed-images.yaml | Deployment `mixed-images-demo` -- all 5 containers (no digest) |
| `image-no-digest` | Low | disallowed-registry.yaml | Deployment `disallowed-registry-demo` -- all 3 containers |
| `image-no-digest` | Low | pull-policy.yaml | Deployment `pull-policy-demo` -- all 4 containers |
| `image-pull-policy` | Medium | pull-policy.yaml | Deployment `pull-policy-demo` -- `mutable-ifnotpresent`, `mutable-default` |
| `image-pull-policy` | Medium | mixed-images.yaml | Deployment `mixed-images-demo` -- `app-mutable` |
| `image-registry-allowlist` | High | disallowed-registry.yaml | Deployment `disallowed-registry-demo` -- `untrusted-app`, `another-unknown` (requires policy config) |
| `image-registry-blocklist` | Critical | disallowed-registry.yaml | Deployment `disallowed-registry-demo` -- `untrusted-app` (requires policy config) |

### Expected minimum finding count

**Without registry policies:** 20+ findings (tag-latest, tag-missing, no-digest, pull-policy)
**With registry policies configured:** 23+ findings (adds allowlist + blocklist findings)

### Severity distribution (without registry policies)

| Severity | Minimum Count |
|----------|---------------|
| Medium | 8+ (image-tag-latest, image-tag-missing, image-pull-policy) |
| Low | 14+ (image-no-digest across all containers in all deployments) |

### Pass criteria

- `image-tag-latest` fires on containers using `:latest` or no tag at all.
- `image-tag-missing` fires only on containers with no tag AND no digest.
- `image-no-digest` fires on every container that lacks `@sha256:...`.
- `image-pull-policy` does NOT fire on containers with `imagePullPolicy: Always`.
- `image-pull-policy` does NOT fire on `:latest` containers (K8s defaults to Always).
- Init containers and native sidecars are scanned (mixed-images.yaml validates this).
- Exit code is `1`.

---

## rbac

**Namespace:** `kv-e2e-rbac`
**Manifest files:** 11 (namespace.yaml + 10 RBAC manifests)

### Checks that should trigger

| Check ID | Severity | Source File | Triggering Resource(s) |
|----------|----------|-------------|------------------------|
| `rbac-wildcard-verbs` | Critical | wildcard-permissions.yaml | Role `kv-e2e-wildcard-verbs` -- `verbs: ["*"]` |
| `rbac-wildcard-resources` | Critical | wildcard-permissions.yaml | ClusterRole `kv-e2e-wildcard-resources` -- `resources: ["*"]` |
| `rbac-wildcard-apigroups` | Critical | wildcard-permissions.yaml | ClusterRole `kv-e2e-wildcard-apigroups` -- `apiGroups: ["*"]` |
| `rbac-escalation-verbs` | Critical | privilege-escalation.yaml | Role `kv-e2e-escalation-verbs` -- verbs escalate, bind, impersonate |
| `rbac-cluster-admin` | Critical | cluster-admin-binding.yaml | ClusterRoleBinding `kv-e2e-cluster-admin-binding` -- references cluster-admin |
| `rbac-secret-access` | High | secret-access.yaml | Role `kv-e2e-secret-access` -- get/list/watch on secrets |
| `rbac-exec-access` | High | exec-log-access.yaml | Role `kv-e2e-exec-log-access` -- create on pods/exec, pods/attach |
| `rbac-log-access` | Medium | exec-log-access.yaml | Role `kv-e2e-exec-log-access` -- get on pods/log |
| `rbac-group-bindings` | High | group-bindings.yaml | ClusterRoleBindings referencing system:authenticated, system:unauthenticated |
| `default-service-account` | High | default-sa-binding.yaml | RoleBinding granting edit to default SA in kv-e2e-rbac |
| `automount-token` | High | service-account-config.yaml | Pod `kv-e2e-automount-pod` -- `automountServiceAccountToken: true` |
| `token-projection-config` | Medium | service-account-config.yaml | Pods `kv-e2e-automount-pod`, `kv-e2e-no-projection-pod` -- no projected token volume |
| `rbac-unused-roles` | Info | unused-role.yaml | Role `kv-e2e-unused-role` -- no binding references it |
| `rbac-subject-external` | Low | overly-broad-roles.yaml | ClusterRoleBinding `kv-e2e-external-user-binding` -- User subject |
| `cloud-iam-binding` | Medium | overly-broad-roles.yaml | ServiceAccount `kv-e2e-cloud-iam-sa` -- AWS IRSA annotation |

### Expected minimum finding count

**18+ findings**

### Severity distribution

| Severity | Minimum Count |
|----------|---------------|
| Critical | 5 (wildcard-verbs, wildcard-resources, wildcard-apigroups, escalation-verbs, cluster-admin) |
| High | 6 (secret-access, exec-access, group-bindings x2, default-service-account, automount-token) |
| Medium | 4 (log-access, token-projection-config x2, cloud-iam-binding) |
| Low | 1 (rbac-subject-external) |
| Info | 1 (rbac-unused-roles) |

### Pass criteria

- All 5 Critical RBAC checks fire.
- `rbac-unused-roles` fires on `kv-e2e-unused-role` but NOT on roles that have bindings.
- `default-service-account` fires on the RoleBinding that targets `default` SA.
- `rbac-cluster-admin` fires on the ClusterRoleBinding referencing `cluster-admin`.
- `rbac-group-bindings` fires on both system:authenticated and system:unauthenticated bindings.
- Exit code is `1`.

---

## network

**Namespace:** `kv-e2e-network` (primary), `kv-e2e-network-deny` (for default-deny tests)
**Manifest files:** 7 (namespace.yaml + 6 network manifests)

### Checks that should trigger

| Check ID | Severity | Source File | Triggering Resource(s) |
|----------|----------|-------------|------------------------|
| `network-policy-missing` | High | namespace.yaml | Namespace `kv-e2e-network` initially has zero NetworkPolicies (before permissive-policy.yaml is applied) |
| `network-policy-default-deny` | High | missing-default-deny.yaml | Namespace `kv-e2e-network-deny` -- policies exist but none is a default-deny (non-empty podSelector) |
| `network-policy-overly-permissive` | Medium | permissive-policy.yaml | NetworkPolicy `allow-all-ingress` (empty from), `allow-all-egress` (0.0.0.0/0) |
| `network-policy-egress-unrestricted` | Medium | namespace.yaml | Namespace `kv-e2e-network` has no egress-type NetworkPolicy |
| `ingress-no-tls` | High | ingress-issues.yaml | All 3 Ingress resources lack TLS configuration |
| `ingress-wildcard-host` | Medium | ingress-issues.yaml | `wildcard-host-ingress` (host: "*"), `no-class-ingress` (empty host) |
| `ingress-class-missing` | Low | ingress-issues.yaml | All 3 Ingress resources lack ingressClassName |
| `service-type-loadbalancer` | Medium | loadbalancer-service.yaml | Service `public-lb` -- type: LoadBalancer |
| `service-type-nodeport` | Medium | nodeport-service.yaml | Service `node-exposed` -- type: NodePort |
| `external-ips` | High | external-ip-service.yaml | Service `hijack-svc` -- externalIPs configured |

### Expected minimum finding count

**16+ findings**

### Severity distribution

| Severity | Minimum Count |
|----------|---------------|
| High | 6 (network-policy-missing, network-policy-default-deny x2, ingress-no-tls x3, external-ips) |
| Medium | 6 (overly-permissive x2, egress-unrestricted, ingress-wildcard-host x2, loadbalancer, nodeport) |
| Low | 3 (ingress-class-missing x3) |

### Pass criteria

- `network-policy-missing` fires on `kv-e2e-network` when no NetworkPolicy exists (before adding permissive-policy.yaml).
- `network-policy-default-deny` fires on `kv-e2e-network-deny` which has scoped policies but no default-deny.
- `ingress-no-tls` fires on all three Ingress resources.
- `ingress-wildcard-host` does NOT fire on `no-tls-ingress` (it has a specific host).
- `external-ips` fires referencing CVE-2020-8554.
- Exit code is `1`.

---

## secrets

**Namespace:** `kv-e2e-secrets`
**Manifest files:** 2 (namespace.yaml + secrets-in-env.yaml)

### Checks that should trigger

| Check ID | Severity | Source File | Triggering Resource(s) |
|----------|----------|-------------|------------------------|
| `secrets-in-env` | Medium | secrets-in-env.yaml | Pod `app-with-secret-env` -- init container `db-init` (1 secretKeyRef), container `app` (3 secretKeyRefs) |

### Expected minimum finding count

**4 findings** (4 individual secretKeyRef usages across 2 containers)

### Severity distribution

| Severity | Minimum Count |
|----------|---------------|
| Medium | 4 |

### Pass criteria

- `secrets-in-env` fires for each `secretKeyRef` usage (DB_PASSWORD in init, DB_USERNAME/DB_PASSWORD/DATABASE_URL in app).
- `configMapKeyRef` references (LOG_LEVEL) do NOT trigger findings.
- Both init containers and regular containers are scanned.
- Exit code is `1`.

---

## psa

**Namespaces:** `kv-e2e-psa`, `kv-e2e-psa-baseline`, `kv-e2e-psa-audit`, `kv-e2e-psa-restricted`, `kv-e2e-psa-pinned`
**Manifest files:** 5

### Checks that should trigger

| Check ID | Severity | Source File | Triggering Resource(s) |
|----------|----------|-------------|------------------------|
| `psa-labels-missing` | Medium | missing-psa-labels.yaml | Namespace `kv-e2e-psa` -- no `pod-security.kubernetes.io/enforce` label |
| `psa-mode-audit-only` | Medium | psa-mode-mismatch.yaml | Namespace `kv-e2e-psa-audit` -- has audit/warn but no enforce |
| `psa-mode-audit-only` | Medium | psa-baseline-violations.yaml | Namespace `kv-e2e-psa-baseline` -- audit/warn only |
| `psa-mode-audit-only` | Medium | psa-restricted-violations.yaml | Namespace `kv-e2e-psa-restricted` -- audit/warn only |
| `psa-baseline-violations` | High | psa-baseline-violations.yaml | Deployments: `host-network-app` (hostNetwork), `privileged-app` (privileged + hostPID), `dangerous-caps-app` (SYS_ADMIN) |
| `psa-restricted-violations` | Medium | psa-restricted-violations.yaml | Deployments: `no-security-context-app` (3 violations), `partial-restricted-app` (2 violations), `explicit-root-app` (3 violations) |
| `psa-version-pinning` | Low | psa-version-pinning.yaml | Namespace `kv-e2e-psa-pinned` -- enforce-version, audit-version, warn-version all pinned to v1.25 |

### Expected minimum finding count

**18+ findings**

### Severity distribution

| Severity | Minimum Count |
|----------|---------------|
| High | 4+ (psa-baseline-violations for hostNetwork, privileged, hostPID, SYS_ADMIN) |
| Medium | 11+ (psa-labels-missing, psa-mode-audit-only x3, psa-restricted-violations x8) |
| Low | 3 (psa-version-pinning x3) |

### Pass criteria

- `psa-labels-missing` fires on `kv-e2e-psa` but NOT on namespaces that have enforce labels.
- `psa-mode-audit-only` fires on namespaces with audit/warn but no enforce.
- `psa-baseline-violations` fires on hostNetwork, privileged, hostPID, and SYS_ADMIN cap additions.
- `psa-restricted-violations` fires for each missing requirement: runAsNonRoot, allowPrivilegeEscalation, capabilities.drop.
- `psa-version-pinning` fires once per pinned version label (3 total).
- The `kv-e2e-psa-pinned` namespace does NOT trigger psa-labels-missing or psa-mode-audit-only (it has enforce).
- Exit code is `1`.

---

## cluster-hardening

**Namespaces:** `default`, `kv-e2e-cluster-no-limits`, `kv-e2e-cluster-no-quota`, `kv-e2e-cluster-proper`
**Manifest files:** 5

### Checks that should trigger

| Check ID | Severity | Source File | Triggering Resource(s) |
|----------|----------|-------------|------------------------|
| `namespace-default-usage` | Medium | default-namespace.yaml | Deployments `kv-e2e-default-web`, `kv-e2e-default-worker` in namespace `default` |
| `limit-range-missing` | Low | missing-limit-ranges.yaml | Namespace `kv-e2e-cluster-no-limits` -- no LimitRange |
| `resource-quota-missing` | Low | missing-resource-quotas.yaml | Namespace `kv-e2e-cluster-no-quota` -- no ResourceQuota |
| `deprecated-api-usage` | Medium | deprecated-apis.yaml | PodSecurityPolicy `kv-e2e-legacy-psp` (policy/v1beta1, removed in K8s 1.25) |

### Checks that should NOT trigger

- `limit-range-missing` should NOT fire on `kv-e2e-cluster-proper` (has LimitRange).
- `resource-quota-missing` should NOT fire on `kv-e2e-cluster-proper` (has ResourceQuota).

### Expected minimum finding count

**5+ findings**

### Severity distribution

| Severity | Minimum Count |
|----------|---------------|
| Medium | 3 (namespace-default-usage x2, deprecated-api-usage) |
| Low | 2 (limit-range-missing, resource-quota-missing) |

### Pass criteria

- `namespace-default-usage` fires on each workload in the `default` namespace.
- `limit-range-missing` and `resource-quota-missing` fire on their respective namespaces.
- `deprecated-api-usage` fires on the PodSecurityPolicy manifest. Note: on K8s 1.25+ clusters this manifest will fail to apply; use manifest mode (`--file`) for this check.
- `proper-quotas.yaml` produces zero findings from quota/limit checks (it is the passing example).
- Exit code is `1`.

---

## scheduling

**Namespace:** `kv-e2e-scheduling`
**Manifest files:** 7 (namespace.yaml + 6 scheduling manifests)

### Checks that should trigger

| Check ID | Severity | Source File | Triggering Resource(s) |
|----------|----------|-------------|------------------------|
| `toleration-control-plane` | High | control-plane-tolerations.yaml | Deployment `control-plane-tolerator` -- tolerates control-plane and master taints |
| `toleration-all` | Medium | tolerate-all.yaml | Deployment `tolerate-everything` -- catch-all toleration (operator: Exists, no key) |
| `priority-class-system` | High | priority-class.yaml | Deployment `system-priority-app` -- uses `system-cluster-critical` in a non-system namespace |
| `priority-class-missing` | Low | priority-class.yaml | Deployment `no-priority-app` -- no `priorityClassName` set |
| `pod-disruption-budget` | Low | missing-pdb.yaml | Deployment `no-pdb-app` -- replicas=3, no PDB |
| `topology-spread` | Low | no-topology-spread.yaml | Deployment `no-topology-spread-app` -- replicas=3, no topologySpreadConstraints |
| `hpa-without-requests` | Medium | hpa-without-requests.yaml | HPA `hpa-no-requests` targeting Deployment with no resource requests |

### Expected minimum finding count

**8+ findings**

### Severity distribution

| Severity | Minimum Count |
|----------|---------------|
| High | 3 (toleration-control-plane x2 for control-plane + master taints, priority-class-system) |
| Medium | 2 (toleration-all, hpa-without-requests) |
| Low | 3 (priority-class-missing, pod-disruption-budget, topology-spread) |

### Pass criteria

- `toleration-control-plane` fires for both the `control-plane` and `master` taint tolerations.
- `toleration-all` fires on the catch-all toleration but NOT on specific tolerations.
- `priority-class-system` fires because the namespace is not `kube-system` or another system namespace.
- `pod-disruption-budget` fires only on multi-replica deployments without a PDB.
- `hpa-without-requests` fires on the HPA, not on the Deployment directly.
- Exit code is `1`.

---

## storage

**Namespace:** `kv-e2e-storage` (cluster-scoped PVs have no namespace)
**Manifest files:** 6 (namespace.yaml + 5 storage manifests)

### Checks that should trigger

| Check ID | Severity | Source File | Triggering Resource(s) |
|----------|----------|-------------|------------------------|
| `emptydir-size-limit` | Low | emptydir-no-limit.yaml | Deployment `emptydir-no-limit` -- emptyDir volume `scratch` has no sizeLimit |
| `projected-volume-security` | Medium | projected-volume.yaml | Pod `projected-permissive` -- projected volume `sa-token` has defaultMode 0644 |
| `pvc-no-encryption` | Medium | no-storage-class.yaml | PVC `data-no-sc` -- no storageClassName specified |
| `pvc-no-encryption` | Medium | permissive-access-modes.yaml | PVC `shared-data-rwx` -- StorageClass `kv-e2e-nfs-unencrypted` has no encryption parameters |
| `pvc-no-encryption` | Medium | hostpath-pv.yaml | PVC `hostpath-claim` -- StorageClass `kv-e2e-manual` has no encryption parameters |
| `pvc-reclaim-retain` | Medium | hostpath-pv.yaml | PV `kv-e2e-hostpath-pv` -- Retain reclaim policy (live mode only, when PV enters Released state) |

### Expected minimum finding count

**5+ findings** (manifest mode); **6+ findings** (live mode with Released PV)

### Severity distribution

| Severity | Minimum Count |
|----------|---------------|
| Medium | 4+ (projected-volume-security, pvc-no-encryption x3) |
| Low | 1 (emptydir-size-limit) |

### Pass criteria

- `emptydir-size-limit` fires on the emptyDir volume without sizeLimit.
- `projected-volume-security` fires because defaultMode 0644 exceeds the safe threshold of 0600.
- `pvc-no-encryption` fires on PVCs referencing StorageClasses without encryption parameters.
- `pvc-reclaim-retain` may only fire in live mode when the PV enters Released state.
- Exit code is `1`.

---

## clean

**Manifest files:** 0 (empty directory)

### Checks that should trigger

**NONE.** This scenario is the negative control. It verifies that scanning an
empty directory or a namespace with only properly configured resources produces
zero findings.

### Expected finding count

**Exactly 0 findings.**

### Pass criteria

- Zero findings in scan output.
- Exit code is `0` (clean scan).
- No error output (exit code is NOT `2` or `3`).

### How to test

```bash
# Manifest mode: scan the empty directory
kubevigil scan --file test/e2e/scenarios/clean/

# Should produce: "No findings" or equivalent, exit code 0
```

---

## mixed

**Namespace:** `kv-e2e-mixed`
**Manifest files:** 2 (namespace.yaml + typical-startup.yaml)

### Checks that should trigger

| Check ID | Severity | Source File | Triggering Resource(s) |
|----------|----------|-------------|------------------------|
| `image-tag-latest` | Medium | typical-startup.yaml | Deployment `startup-web-app` -- container `web` uses nginx:latest |
| `image-no-digest` | Low | typical-startup.yaml | Deployment `startup-web-app` -- no digest pinning |
| `run-as-root` | High | typical-startup.yaml | Deployment `startup-web-app` -- no runAsNonRoot, no runAsUser |
| `read-only-rootfs` | Medium | typical-startup.yaml | Deployment `startup-web-app` -- no readOnlyRootFilesystem |
| `capabilities-not-dropped` | Medium | typical-startup.yaml | Deployment `startup-web-app` -- no `drop: ["ALL"]` |
| `seccomp-profile` | Medium | typical-startup.yaml | Deployment `startup-web-app` -- no seccomp profile |
| `privilege-escalation` | High | typical-startup.yaml | Deployment `startup-web-app` -- allowPrivilegeEscalation not false |
| `resource-limits-missing` | Medium | typical-startup.yaml | Deployment `startup-web-app` -- no resource limits |
| `resource-requests-missing` | Medium | typical-startup.yaml | Deployment `startup-web-app` -- no resource requests |
| `liveness-readiness-probes` | Low | typical-startup.yaml | Deployment `startup-web-app` -- no probes defined |

### Additional findings in live mode

| Check ID | Severity | Notes |
|----------|----------|-------|
| `network-policy-missing` | High | Namespace `kv-e2e-mixed` has no NetworkPolicy |
| `default-service-account` | High | Pod uses default ServiceAccount |
| `automount-token` | High | Token automounted by default |
| `pod-disruption-budget` | Low | replicas=2, no PDB |

### Expected minimum finding count

**Manifest mode:** 10+ findings
**Live mode:** 14+ findings (adds namespace-level and cluster-level checks)

### Severity distribution (manifest mode)

| Severity | Minimum Count |
|----------|---------------|
| High | 2 (run-as-root, privilege-escalation) |
| Medium | 6 (image-tag-latest, read-only-rootfs, capabilities-not-dropped, seccomp-profile, resource-limits, resource-requests) |
| Low | 2 (image-no-digest, liveness-readiness-probes) |

### Pass criteria

- Multiple check categories fire on a single Deployment (cross-category validation).
- At least 3 different severity levels are represented in findings.
- The same container (`web`) is referenced by multiple checks.
- This scenario validates that KubeVigil handles "real-world" multi-issue manifests correctly.
- Exit code is `1`.

---

## Summary Table

| Scenario | Min Findings | Critical | High | Medium | Low | Info | Exit Code |
|----------|-------------|----------|------|--------|-----|------|-----------|
| workload-security | 35 | 7 | 7 | 15 | 6 | 0 | 1 |
| image-security | 20 | 0* | 0* | 8 | 14 | 0 | 1 |
| rbac | 18 | 5 | 6 | 4 | 1 | 1 | 1 |
| network | 16 | 0 | 6 | 6 | 3 | 0 | 1 |
| secrets | 4 | 0 | 0 | 4 | 0 | 0 | 1 |
| psa | 18 | 0 | 4 | 11 | 3 | 0 | 1 |
| cluster-hardening | 5 | 0 | 0 | 3 | 2 | 0 | 1 |
| scheduling | 8 | 0 | 3 | 2 | 3 | 0 | 1 |
| storage | 5 | 0 | 0 | 4 | 1 | 0 | 1 |
| clean | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| mixed | 10 | 0 | 2 | 6 | 2 | 0 | 1 |

*image-security has Critical/High findings only when registry policies are configured.

---

## Notes

1. **Finding counts are minimums.** Some checks may produce additional findings
   depending on the exact checker implementation (e.g., one finding per container
   vs. one per pod).

2. **Live mode vs. manifest mode.** Namespace-level checks (network-policy-missing,
   limit-range-missing, resource-quota-missing) and cluster-level checks only fire
   in live mode. Manifest mode scans only the YAML content.

3. **Registry policy checks.** `image-registry-allowlist` and `image-registry-blocklist`
   require a `.kubevigil.yaml` configuration with `allowedRegistries` and/or
   `blockedRegistries` lists. Without configuration, these checks are no-ops.

4. **Deprecated API manifests.** The `deprecated-apis.yaml` file (PodSecurityPolicy)
   will be rejected by K8s 1.25+ API servers. Use manifest mode for this test.

5. **PVC reclaim findings.** `pvc-reclaim-retain` may only fire in live mode when
   a PV enters the Released state. In manifest mode, the PV exists but is not in
   that state.

---

## Fix Scenarios — Expected Findings (Before/After)

The fix scenarios test the `kubevigil fix` command. Each scenario has expected
findings before the fix and expected results after applying fixes at each risk level.

### fix-safe

**Before fix:**

| Check ID | Severity | Resource | Fix Safety |
|----------|----------|----------|------------|
| `privileged` | Critical | privileged-deploy, multi-container-insecure | Safe |
| `privilege-escalation` | High | privileged-deploy, multi-container-insecure | Safe |
| `host-pid` | Critical | multi-container-insecure | Safe |
| `host-ipc` | Critical | multi-container-insecure | Safe |

**After fix (--risk-level safe):** All above findings resolved. Other findings
(capabilities-not-dropped, run-as-root, etc.) remain because they require moderate risk level.

### fix-moderate

**Before fix:**

| Check ID | Severity | Resource | Fix Safety |
|----------|----------|----------|------------|
| `privilege-escalation` | High | missing-sec-ctx | Safe |
| `run-as-root` | High | missing-sec-ctx | Likely Safe |
| `read-only-rootfs` | Medium | missing-sec-ctx | Likely Safe |
| `capabilities-not-dropped` | Medium | missing-sec-ctx | Likely Safe |
| `seccomp-profile` | Medium | missing-sec-ctx | Likely Safe |

**After fix (--risk-level safe):** Only `privilege-escalation` resolved.
**After fix (--risk-level moderate):** All above findings resolved.

### fix-aggressive

**Before fix:**

| Check ID | Severity | Resource | Fix Safety |
|----------|----------|----------|------------|
| `resource-limits-missing` | Medium | missing-resources | Potentially Breaking |
| `resource-requests-missing` | Medium | missing-resources | Potentially Breaking |
| `ephemeral-storage-limits` | Low | missing-resources | Potentially Breaking |
| `host-ports` | High | host-port-deploy | Potentially Breaking |

**After fix (--risk-level safe):** No findings resolved (all potentially breaking).
**After fix (--risk-level moderate):** No findings resolved (all potentially breaking).
**After fix (--risk-level aggressive):** All above findings resolved.

### fix-system-ns

**Before fix:**

| Check ID | Severity | Resource | Fix Safety |
|----------|----------|----------|------------|
| `privileged` | Critical | system-daemon (kube-system) | Safe |
| `privilege-escalation` | High | system-daemon (kube-system) | Safe |

**After fix (any risk level, no --i-understand-system-namespaces):**
No findings resolved — system namespace protection blocks all fixes.

### fix-known-workloads

| Resource | Image | Detection | Expected Behavior |
|----------|-------|-----------|-------------------|
| calico-node | `calico/node:v3.27.0` | CNI plugin | Skip — needs privileged, hostNetwork |
| coredns | `registry.k8s.io/coredns/coredns:v1.11.1` | Core DNS | Skip — system workload |
| node-exporter | `prom/node-exporter:v1.7.0` | Monitoring | Skip — needs hostPID, hostNetwork |

All three resources should be skipped (known workloads + system namespaces).

### fix-multi-doc

Three documents: insecure Deployment, Service, insecure Deployment.
After fix: Both deployments have `privileged: false`. Service unchanged.
Document separators (`---`) preserved.

### fix-comments

Single deployment with extensive comments. After fix: `privileged: true` changed
to `privileged: false`. All comments preserved (head, inline, block).

### fix-clean

Fully hardened deployment. `kubevigil fix` reports "No fixable findings" and
exits with code 4.

### fix-partial-failure

Three files: valid insecure, malformed YAML, read-only insecure.
After fix (--apply): valid file fixed, malformed skipped (parse error),
read-only skipped (permission denied). Exit code 5 (partial success) when
read-only file is actually chmod 444.
