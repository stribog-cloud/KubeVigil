# NSA/CISA Kubernetes Hardening Guide v1.2

The NSA/CISA Kubernetes Hardening Guide is a technical report published jointly by the US National Security Agency and the Cybersecurity and Infrastructure Security Agency. It provides practical guidance for hardening Kubernetes environments against common attack vectors, organized by security domain.

KubeVigil maps its checks to the sections of this guide, enabling organizations to assess compliance with US government hardening recommendations.

## Usage

```bash
kubevigil scan --framework nsa
```

To generate an NSA/CISA-focused report:

```bash
kubevigil scan --framework nsa -o json > nsa-report.json
kubevigil scan --framework nsa -o report.html
```

## Section Mappings

### Section 1 -- Kubernetes Pod Security

#### 1.1 Non-root containers

| KubeVigil Check | Description |
|-----------------|-------------|
| `privileged` | Detects containers running in privileged mode |
| `capabilities-added` | Detects containers with dangerous added capabilities |
| `capabilities-not-dropped` | Detects containers that have not dropped all capabilities |
| `run-as-root` | Detects containers running as root user |
| `run-as-high-uid` | Detects containers running with high-privilege UIDs |
| `run-as-group` | Detects containers without a group ID set |
| `privilege-escalation` | Detects containers with allowPrivilegeEscalation enabled |

#### 1.2 Immutable container filesystems

| KubeVigil Check | Description |
|-----------------|-------------|
| `read-only-rootfs` | Detects containers without a read-only root filesystem |

#### 1.3 Minimized host resource access

| KubeVigil Check | Description |
|-----------------|-------------|
| `host-pid` | Detects pods sharing the host PID namespace |
| `host-ipc` | Detects pods sharing the host IPC namespace |
| `host-network` | Detects pods sharing the host network namespace |
| `host-ports` | Detects containers using host ports |
| `host-path-volumes` | Detects pods mounting host path volumes |
| `proc-mount` | Detects containers with non-default proc mount settings |
| `share-process-namespace` | Detects pods with shared process namespaces |
| `toleration-control-plane` | Detects pods tolerating control plane taints |
| `toleration-all` | Detects pods tolerating all taints |
| `node-affinity-untrusted` | Detects pods with affinity to untrusted nodes |
| `csi-driver-security` | Detects insecure CSI driver configurations |
| `container-runtime-socket` | Detects containers with access to the container runtime socket |
| `lifecycle-hooks` | Detects lifecycle hooks that could be exploited |

#### 1.4 Trusted container images

| KubeVigil Check | Description |
|-----------------|-------------|
| `image-tag-latest` | Detects images using the `latest` tag |
| `image-tag-missing` | Detects images with missing tags |
| `image-no-digest` | Detects images without a digest |
| `image-pull-policy` | Detects images without `Always` pull policy |
| `image-registry-allowlist` | Detects images from non-allowed registries |
| `image-registry-blocklist` | Detects images from blocked registries |
| `image-signature-verification` | Detects unsigned images |
| `image-sbom-attestation` | Detects images without SBOM attestations |
| `image-provenance` | Detects images without provenance attestations |
| `image-age` | Detects outdated container images |

#### 1.5 Resource requests and limits

| KubeVigil Check | Description |
|-----------------|-------------|
| `resource-limits-missing` | Detects containers without resource limits |
| `resource-requests-missing` | Detects containers without resource requests |
| `resource-limits-ratio` | Detects excessive limits-to-requests ratios |
| `ephemeral-storage-limits` | Detects containers without ephemeral storage limits |
| `priority-class-system` | Detects pods using system priority classes |
| `priority-class-missing` | Detects pods without priority classes |
| `pod-disruption-budget` | Detects deployments without PodDisruptionBudgets |
| `topology-spread` | Detects deployments without topology spread constraints |
| `hpa-without-requests` | Detects HPA targets without resource requests |
| `emptydir-size-limit` | Detects emptyDir volumes without size limits |
| `limit-range-missing` | Detects namespaces without LimitRanges |
| `resource-quota-missing` | Detects namespaces without ResourceQuotas |
| `liveness-readiness-probes` | Detects containers without liveness/readiness probes |
| `startup-probes` | Detects containers without startup probes |

### Section 2 -- Pod Security Enforcement

#### 2.1 Pod security enforcement

| KubeVigil Check | Description |
|-----------------|-------------|
| `seccomp-profile` | Detects containers without a seccomp profile |
| `apparmor-profile` | Detects containers without an AppArmor profile |
| `selinux-options` | Detects containers without SELinux options |
| `unsafe-sysctls` | Detects pods using unsafe sysctls |
| `runtime-class` | Detects pods without a RuntimeClass |
| `ephemeral-container-policy` | Detects missing ephemeral container policies |
| `psa-labels-missing` | Detects namespaces without Pod Security Admission labels |
| `psa-mode-audit-only` | Detects PSA labels set to audit-only mode |
| `psa-baseline-violations` | Detects baseline PSA policy violations |
| `psa-restricted-violations` | Detects restricted PSA policy violations |
| `psa-version-pinning` | Detects PSA labels without version pinning |
| `psp-still-present` | Detects deprecated PodSecurityPolicy resources |
| `privileged` | Detects containers running in privileged mode |
| `capabilities-added` | Detects containers with dangerous added capabilities |
| `privilege-escalation` | Detects containers with allowPrivilegeEscalation enabled |
| `admission-controllers` | Detects missing admission controllers |
| `crd-validation-missing` | Detects CRDs without validation schemas |
| `crd-conversion-webhook` | Detects insecure CRD conversion webhooks |

### Section 3 -- Authentication and Authorization

#### 3.1 RBAC policies

| KubeVigil Check | Description |
|-----------------|-------------|
| `default-service-account` | Detects active use of default service accounts |
| `rbac-wildcard-verbs` | Detects roles with wildcard verb permissions |
| `rbac-wildcard-resources` | Detects roles with wildcard resource permissions |
| `rbac-wildcard-apigroups` | Detects roles with wildcard API group permissions |
| `rbac-escalation-verbs` | Detects roles with bind/impersonate/escalate verbs |
| `rbac-secret-access` | Detects roles with broad secret access |
| `rbac-exec-access` | Detects roles with pod exec permissions |
| `rbac-log-access` | Detects roles with pod log access |
| `rbac-cluster-admin` | Detects cluster-admin role bindings |
| `rbac-unused-roles` | Detects unused roles and cluster roles |
| `rbac-group-bindings` | Detects bindings to system:masters group |
| `rbac-subject-external` | Detects bindings to external subjects |
| `cloud-iam-binding` | Detects cloud IAM role bindings |
| `namespace-default-usage` | Detects resources in the default namespace |
| `api-server-anonymous` | Detects anonymous API server access |
| `kubelet-config` | Detects insecure kubelet configuration |

#### 3.2 Service account management

| KubeVigil Check | Description |
|-----------------|-------------|
| `default-service-account` | Detects active use of default service accounts |
| `automount-token` | Detects automatic service account token mounting |
| `token-projection-config` | Detects token projection misconfigurations |
| `cloud-iam-binding` | Detects cloud IAM role bindings |
| `eks-imds-access` | Detects unrestricted IMDS access on EKS |
| `gke-metadata-concealment` | Detects disabled metadata concealment on GKE |
| `aks-pod-identity` | Detects insecure pod identity on AKS |

### Section 4 -- Network Security

#### 4.1 Network separation

| KubeVigil Check | Description |
|-----------------|-------------|
| `host-network` | Detects pods sharing the host network namespace |
| `network-policy-missing` | Detects namespaces without network policies |
| `ingress-wildcard-host` | Detects ingress resources with wildcard hosts |
| `ingress-class-missing` | Detects ingress resources without an ingress class |
| `service-type-loadbalancer` | Detects LoadBalancer-type services |
| `service-type-nodeport` | Detects NodePort-type services |
| `external-ips` | Detects services with external IPs |
| `dns-security` | Detects DNS security misconfigurations |

#### 4.2 Network policy enforcement

| KubeVigil Check | Description |
|-----------------|-------------|
| `network-policy-missing` | Detects namespaces without network policies |
| `network-policy-default-deny` | Detects missing default-deny network policies |
| `network-policy-overly-permissive` | Detects overly permissive network policies |
| `network-policy-egress-unrestricted` | Detects unrestricted egress policies |

#### 4.3 TLS encryption

| KubeVigil Check | Description |
|-----------------|-------------|
| `ingress-no-tls` | Detects ingress resources without TLS |
| `service-mesh-mtls` | Detects service mesh configurations without mTLS |
| `cert-manager-expiry` | Detects expiring certificates |
| `cert-manager-insecure` | Detects insecure certificate configurations |

### Section 5 -- Data Protection

#### 5.1 Secrets management

| KubeVigil Check | Description |
|-----------------|-------------|
| `secrets-in-env` | Detects secrets passed as environment variables |
| `secrets-in-configmap` | Detects secrets stored in ConfigMaps |
| `secrets-default-type` | Detects secrets with default type |
| `secrets-stale` | Detects stale secrets |
| `secrets-hardcoded-manifests` | Detects hardcoded secrets in manifests |
| `external-secrets-sync` | Detects external secrets sync issues |
| `rbac-secret-access` | Detects roles with broad secret access |
| `pvc-reclaim-retain` | Detects PVCs without proper reclaim policies |
| `projected-volume-security` | Detects insecure projected volume configurations |
| `secrets-unencrypted` | Detects unencrypted secrets |

#### 5.2 Encryption at rest

| KubeVigil Check | Description |
|-----------------|-------------|
| `secrets-unencrypted` | Detects unencrypted secrets |
| `pvc-no-encryption` | Detects unencrypted persistent volumes |
| `etcd-encryption` | Detects missing etcd encryption |

### Section 6 -- Logging and Monitoring

#### 6.1 Audit logging

| KubeVigil Check | Description |
|-----------------|-------------|
| `audit-logging` | Detects missing or misconfigured audit logging |

### Section 7 -- Upgrade and Patching

#### 7.1 Upgrade and patching

| KubeVigil Check | Description |
|-----------------|-------------|
| `component-versions` | Detects outdated Kubernetes component versions |
| `deprecated-api-usage` | Detects usage of deprecated APIs |
| `cloud-provider-detection` | Detects cloud provider configuration issues |

## Notes

- The NSA/CISA guide uses a section-based structure rather than numbered controls. KubeVigil maps to sections using dot notation (e.g., 1.1, 4.2).
- Some checks map to multiple sections. For example, `host-network` maps to both 1.3 (Minimized host resource access) and 4.1 (Network separation).
- Some checks appear under multiple NSA sections because the guide addresses the same concern from different perspectives (e.g., `default-service-account` maps to both 3.1 and 3.2).
