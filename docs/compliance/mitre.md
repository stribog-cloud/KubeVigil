# MITRE ATT&CK for Containers v14

MITRE ATT&CK is a knowledge base of adversary tactics and techniques based on real-world observations. The Containers matrix within ATT&CK v14 describes how attackers target container environments, from initial access through lateral movement to impact.

KubeVigil maps its checks to MITRE ATT&CK techniques, allowing security teams to understand which attack vectors each finding exposes and prioritize remediation based on threat models.

## Usage

```bash
kubevigil scan --framework mitre
```

To generate a MITRE-focused report:

```bash
kubevigil scan --framework mitre -o json > mitre-report.json
kubevigil scan --framework mitre -o report.html
```

## Technique Mappings by Tactic

### Initial Access

| Technique ID | Technique Name | KubeVigil Check(s) |
|-------------|----------------|---------------------|
| T1190 | Exploit Public-Facing Application | `ingress-wildcard-host`, `ingress-class-missing`, `service-type-loadbalancer`, `service-type-nodeport`, `external-ips` |
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | `image-sbom-attestation`, `image-provenance`, `image-age` |

### Execution

| Technique ID | Technique Name | KubeVigil Check(s) |
|-------------|----------------|---------------------|
| T1059 | Command and Scripting Interpreter | `lifecycle-hooks` |
| T1203 | Exploitation for Client Execution | `component-versions`, `deprecated-api-usage` |
| T1609 | Container Administration Command | `rbac-exec-access` |
| T1610 | Deploy Container | `ephemeral-container-policy`, `image-registry-allowlist`, `image-registry-blocklist`, `psa-labels-missing`, `psa-mode-audit-only`, `psa-version-pinning`, `psp-still-present`, `toleration-all`, `node-affinity-untrusted`, `admission-controllers`, `container-runtime-socket`, `crd-validation-missing` |

### Persistence

| Technique ID | Technique Name | KubeVigil Check(s) |
|-------------|----------------|---------------------|
| T1525 | Implant Internal Image | `image-tag-latest`, `image-tag-missing`, `image-no-digest`, `image-pull-policy`, `image-registry-allowlist`, `image-registry-blocklist`, `image-signature-verification` |
| T1078 | Valid Accounts | `rbac-wildcard-verbs`, `rbac-wildcard-resources`, `rbac-wildcard-apigroups`, `rbac-escalation-verbs`, `rbac-cluster-admin`, `rbac-unused-roles`, `rbac-group-bindings`, `rbac-subject-external` |
| T1078.001 | Valid Accounts: Default Accounts | `default-service-account`, `namespace-default-usage`, `api-server-anonymous` |
| T1078.004 | Valid Accounts: Cloud Accounts | `cloud-iam-binding`, `aks-pod-identity` |

### Privilege Escalation

| Technique ID | Technique Name | KubeVigil Check(s) |
|-------------|----------------|---------------------|
| T1068 | Exploitation for Privilege Escalation | `capabilities-added`, `capabilities-not-dropped`, `run-as-high-uid`, `run-as-group`, `selinux-options`, `privilege-escalation`, `rbac-escalation-verbs` |
| T1611 | Escape to Host | `privileged`, `capabilities-added`, `run-as-root`, `host-pid`, `host-ipc`, `host-network`, `host-ports`, `host-path-volumes`, `privilege-escalation`, `seccomp-profile`, `apparmor-profile`, `proc-mount`, `unsafe-sysctls`, `runtime-class`, `toleration-control-plane`, `psa-baseline-violations`, `psa-restricted-violations`, `csi-driver-security`, `container-runtime-socket` |

### Defense Evasion

| Technique ID | Technique Name | KubeVigil Check(s) |
|-------------|----------------|---------------------|
| T1562.008 | Impair Defenses: Disable Cloud Logs | `audit-logging` |

### Credential Access

| Technique ID | Technique Name | KubeVigil Check(s) |
|-------------|----------------|---------------------|
| T1552 | Unsecured Credentials | `secrets-in-env`, `secrets-unencrypted`, `secrets-in-configmap`, `secrets-default-type`, `secrets-stale`, `external-secrets-sync`, `rbac-secret-access`, `etcd-encryption`, `projected-volume-security`, `cert-manager-expiry` |
| T1552.001 | Unsecured Credentials: Credentials In Files | `secrets-hardcoded-manifests` |
| T1552.005 | Unsecured Credentials: Cloud Instance Metadata API | `eks-imds-access`, `gke-metadata-concealment` |
| T1552.007 | Unsecured Credentials: Container API | `automount-token`, `token-projection-config`, `kubelet-config` |

### Discovery

| Technique ID | Technique Name | KubeVigil Check(s) |
|-------------|----------------|---------------------|
| T1046 | Network Service Discovery | `network-policy-missing`, `network-policy-default-deny`, `network-policy-overly-permissive` |
| T1057 | Process Discovery | `host-pid`, `share-process-namespace` |
| T1580 | Cloud Infrastructure Discovery | `cloud-provider-detection` |

### Lateral Movement

| Technique ID | Technique Name | KubeVigil Check(s) |
|-------------|----------------|---------------------|
| T1040 | Network Sniffing | `host-network`, `ingress-no-tls`, `service-mesh-mtls` |
| T1557 | Adversary-in-the-Middle | `ingress-no-tls`, `service-mesh-mtls`, `crd-conversion-webhook`, `cert-manager-insecure` |

### Collection

| Technique ID | Technique Name | KubeVigil Check(s) |
|-------------|----------------|---------------------|
| T1006 | Direct Volume Access | `host-path-volumes` |
| T1530 | Data from Cloud Storage | `rbac-log-access`, `pvc-no-encryption`, `pvc-reclaim-retain` |

### Exfiltration

| Technique ID | Technique Name | KubeVigil Check(s) |
|-------------|----------------|---------------------|
| T1048 | Exfiltration Over Alternative Protocol | `network-policy-egress-unrestricted` |

### Impact

| Technique ID | Technique Name | KubeVigil Check(s) |
|-------------|----------------|---------------------|
| T1071 | Application Layer Protocol | `network-policy-default-deny` |
| T1071.004 | Application Layer Protocol: DNS | `dns-security` |
| T1499 | Endpoint Denial of Service | `resource-limits-missing`, `resource-requests-missing`, `resource-limits-ratio`, `ephemeral-storage-limits`, `priority-class-system`, `priority-class-missing`, `pod-disruption-budget`, `topology-spread`, `hpa-without-requests`, `emptydir-size-limit`, `limit-range-missing`, `resource-quota-missing`, `liveness-readiness-probes`, `startup-probes` |
| T1565.001 | Stored Data Manipulation | `read-only-rootfs` |

## Notes

- Multiple checks can map to the same technique. For example, T1611 (Escape to Host) is mapped by 19 checks because there are many container escape vectors.
- A single check can map to multiple techniques across different tactics. For example, `host-pid` maps to both T1611 (Escape to Host) and T1057 (Process Discovery).
- MITRE technique IDs with sub-techniques use dot notation (e.g., T1552.007 is a sub-technique of T1552).
