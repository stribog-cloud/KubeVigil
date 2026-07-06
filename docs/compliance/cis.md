# CIS Kubernetes Benchmark v1.8

The Center for Internet Security (CIS) Kubernetes Benchmark provides prescriptive hardening guidance for Kubernetes clusters. It is the most widely adopted standard for Kubernetes security compliance, used by organizations to establish baseline security configurations and demonstrate due diligence during audits.

KubeVigil maps its checks to CIS Benchmark v1.8 controls across Sections 1 (Control Plane), 4 (Worker Nodes), and 5 (Policies).

## Usage

```bash
kubevigil scan --framework cis
```

To generate a CIS-focused report in a specific format:

```bash
kubevigil scan --framework cis -o json > cis-report.json
kubevigil scan --framework cis -o report.html
```

## Control Mappings

### Section 1.2 -- API Server

| CIS Control ID | Control Title | KubeVigil Check(s) |
|-----------------|---------------|---------------------|
| 1.2.1 | Ensure that the `--anonymous-auth` argument is set to false | `api-server-anonymous` |
| 1.2.11 | Ensure that the admission control plugin AlwaysPullImages is set | `admission-controllers` |
| 1.2.17 | Ensure that the `--audit-log-path` argument is set | `audit-logging` |
| 1.2.18 | Ensure that the `--audit-log-maxage` argument is set to 30 or as appropriate | `audit-logging` |
| 1.2.28 | Ensure that the `--encryption-provider-config` argument is set as appropriate | `secrets-unencrypted`, `etcd-encryption` |
| 1.2.29 | Ensure that encryption providers are appropriately configured | `secrets-unencrypted`, `etcd-encryption` |

### Section 4.2 -- Kubelet

| CIS Control ID | Control Title | KubeVigil Check(s) |
|-----------------|---------------|---------------------|
| 4.2.1 | Ensure that the `--anonymous-auth` argument is set to false | `kubelet-config` |

### Section 5.1 -- RBAC and Service Accounts

| CIS Control ID | Control Title | KubeVigil Check(s) |
|-----------------|---------------|---------------------|
| 5.1.1 | Ensure that the cluster-admin role is only used where required | `rbac-wildcard-verbs`, `rbac-escalation-verbs`, `rbac-exec-access`, `rbac-log-access`, `rbac-cluster-admin`, `rbac-unused-roles`, `rbac-group-bindings`, `rbac-subject-external`, `cloud-iam-binding` |
| 5.1.2 | Minimize access to secrets | `rbac-secret-access` |
| 5.1.3 | Minimize wildcard use in Roles and ClusterRoles | `rbac-wildcard-verbs`, `rbac-wildcard-resources`, `rbac-wildcard-apigroups` |
| 5.1.5 | Ensure that default service accounts are not actively used | `default-service-account` |
| 5.1.6 | Ensure that Service Account Tokens are only mounted where necessary | `default-service-account`, `automount-token`, `token-projection-config` |
| 5.1.7 | Avoid use of system:masters group | `rbac-group-bindings` |
| 5.1.8 | Limit use of the Bind, Impersonate and Escalate permissions | `rbac-escalation-verbs` |

### Section 5.2 -- Pod Security Standards

| CIS Control ID | Control Title | KubeVigil Check(s) |
|-----------------|---------------|---------------------|
| 5.2.1 | Ensure that the cluster has at least one active policy control mechanism in place | `ephemeral-container-policy`, `psa-labels-missing`, `psa-mode-audit-only`, `psa-baseline-violations`, `psa-restricted-violations`, `psa-version-pinning`, `psp-still-present` |
| 5.2.2 | Minimize the admission of privileged containers | `privileged` |
| 5.2.3 | Minimize the admission of containers wishing to share the host process ID namespace | `host-pid` |
| 5.2.4 | Minimize the admission of containers wishing to share the host IPC namespace | `host-ipc` |
| 5.2.5 | Minimize the admission of containers wishing to share the host network namespace | `host-network` |
| 5.2.6 | Minimize the admission of containers with allowPrivilegeEscalation | `privilege-escalation` |
| 5.2.7 | Minimize the admission of root containers | `run-as-root`, `run-as-high-uid`, `run-as-group` |
| 5.2.8 | Minimize the admission of containers with the NET_RAW capability | `capabilities-not-dropped` |
| 5.2.9 | Minimize the admission of containers with added capabilities | `capabilities-added` |
| 5.2.10 | Minimize the admission of containers with capabilities assigned | `capabilities-added`, `capabilities-not-dropped` |
| 5.2.12 | Minimize the admission of HostPath volumes | `host-path-volumes`, `container-runtime-socket` |
| 5.2.13 | Minimize the admission of containers which use HostPorts | `host-ports` |

### Section 5.3 -- Network Policies and CNI

| CIS Control ID | Control Title | KubeVigil Check(s) |
|-----------------|---------------|---------------------|
| 5.3.1 | Ensure that the CNI in use supports Network Policies | `dns-security` |
| 5.3.2 | Ensure that all Namespaces have Network Policies defined | `network-policy-missing`, `network-policy-default-deny`, `network-policy-overly-permissive`, `network-policy-egress-unrestricted`, `ingress-no-tls`, `ingress-wildcard-host`, `ingress-class-missing`, `service-type-loadbalancer`, `service-type-nodeport`, `external-ips`, `service-mesh-mtls`, `network-policy-empty-namespace-selector` |

### Section 5.4 -- Secrets Management

| CIS Control ID | Control Title | KubeVigil Check(s) |
|-----------------|---------------|---------------------|
| 5.4.1 | Prefer using secrets as files over secrets as environment variables | `secrets-in-env`, `secrets-in-configmap`, `secrets-default-type`, `secrets-hardcoded-manifests`, `projected-volume-security`, `cert-manager-expiry`, `cert-manager-insecure`, `secrets-envfrom-bulk`, `secrets-tls-weak-key`, `secrets-in-annotations` |
| 5.4.2 | Consider external secret storage | `secrets-in-env`, `secrets-stale`, `external-secrets-sync`, `pvc-no-encryption` |

### Section 5.5 -- Extensible Admission Control

| CIS Control ID | Control Title | KubeVigil Check(s) |
|-----------------|---------------|---------------------|
| 5.5.1 | Configure Image Provenance using ImagePolicyWebhook admission controller | `image-tag-latest`, `image-tag-missing`, `image-no-digest`, `image-pull-policy`, `image-registry-allowlist`, `image-registry-blocklist`, `image-signature-verification`, `image-sbom-attestation`, `image-provenance`, `crd-conversion-webhook`, `image-age` |

### Section 5.6 -- General Policies

| CIS Control ID | Control Title | KubeVigil Check(s) |
|-----------------|---------------|---------------------|
| 5.6.1 | Create administrative boundaries between resources using namespaces | `deprecated-api-usage` |
| 5.6.2 | Ensure that the seccomp profile is set to docker/default in your pod definitions | `seccomp-profile` |
| 5.6.3 | Apply Security Context to Your Pods and Containers | `read-only-rootfs`, `resource-limits-missing`, `resource-requests-missing`, `resource-limits-ratio`, `ephemeral-storage-limits`, `apparmor-profile`, `selinux-options`, `proc-mount`, `unsafe-sysctls`, `runtime-class`, `share-process-namespace`, `toleration-control-plane`, `toleration-all`, `priority-class-system`, `priority-class-missing`, `pod-disruption-budget`, `topology-spread`, `node-affinity-untrusted`, `hpa-without-requests`, `pvc-reclaim-retain`, `csi-driver-security`, `emptydir-size-limit`, `limit-range-missing`, `resource-quota-missing`, `component-versions`, `liveness-readiness-probes`, `startup-probes`, `lifecycle-hooks`, `eks-imds-access`, `gke-metadata-concealment`, `aks-pod-identity`, `cloud-provider-detection`, `crd-validation-missing` |
| 5.6.4 | The default namespace should not be used | `namespace-default-usage` |

## Notes

- A single KubeVigil check can map to multiple CIS controls. For example, `capabilities-added` maps to both 5.2.9 and 5.2.10.
- A single CIS control can be covered by multiple KubeVigil checks. For example, CIS 5.6.3 is a broad control covered by many workload, scheduling, and storage checks.
- CIS control 5.6.3 ("Apply Security Context to Your Pods and Containers") is intentionally broad in the CIS Benchmark and serves as a catch-all for security context best practices.
