# Cluster Configuration Checks

KubeVigil includes 10 checks that detect cluster-level misconfigurations across namespaces, API server settings, admission controllers, etcd encryption, kubelet configuration, version skew, and deprecated API usage.

## Checks

### `namespace-default-usage`
**Severity:** Medium · **Modes:** Live, Manifest · **Auto-fix:** No

Detects workloads deployed in the `default` namespace. The default namespace is a shared, unsecured space that typically lacks resource quotas, network policies, and RBAC boundaries. Workloads deployed here are exposed to cross-tenant access and resource contention.

**Remediation:**
Create a dedicated namespace for your workload and apply security labels:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: my-app
  labels:
    pod-security.kubernetes.io/enforce: restricted
---
apiVersion: apps/v1
kind: Deployment
metadata:
  namespace: my-app    # Move out of default
```

Apply NetworkPolicies and ResourceQuotas to the new namespace for full isolation.

---

### `limit-range-missing`
**Severity:** Low · **Modes:** Live, Manifest · **Auto-fix:** No

Detects non-system namespaces without a LimitRange defined. Without a LimitRange, any container can be created without resource constraints, allowing a single runaway or malicious pod to consume all node CPU and memory, causing denial of service for other workloads on the same node.

**Remediation:**
Create a LimitRange in the namespace to set default and maximum resource constraints. Containers that omit resource requests/limits will inherit these defaults automatically:

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

---

### `resource-quota-missing`
**Severity:** Low · **Modes:** Live, Manifest · **Auto-fix:** No

Detects non-system namespaces without a ResourceQuota defined. Without a ResourceQuota, a single namespace can consume the entire cluster's CPU, memory, and storage, creating a noisy-neighbor problem where one team's workloads starve others and making capacity planning impossible.

**Remediation:**
Create a ResourceQuota to cap the namespace's total resource consumption. Tune quota values based on actual workload requirements and cluster capacity:

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

---

### `api-server-anonymous`
**Severity:** High · **Modes:** Live only · **Auto-fix:** No

Detects when the API server has anonymous authentication enabled (`--anonymous-auth=true`). The check inspects `kubeadm-config` and `kube-apiserver` ConfigMaps in `kube-system`. Anonymous authentication allows any unauthenticated user to make API server requests, enabling attackers to enumerate cluster resources and exploit misconfigured RBAC rules granting permissions to `system:anonymous` or `system:unauthenticated`.

> **Note:** This check runs only in Live mode because it requires access to kube-system ConfigMaps containing API server configuration.

**Remediation:**
Disable anonymous authentication on the API server. On managed clusters (EKS, GKE, AKS), anonymous auth is typically disabled by default:

```yaml
# In kube-apiserver manifest or configuration:
apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
spec:
  containers:
    - command:
        - kube-apiserver
        - --anonymous-auth=false
```

---

### `audit-logging`
**Severity:** High · **Modes:** Live only · **Auto-fix:** No

Detects when API server audit logging is not configured. The check looks for audit policy ConfigMaps in `kube-system` or audit-related flags (`--audit-policy-file`, `--audit-log-path`) in the API server configuration. Without audit logging, there is no record of who accessed the API server, what they changed, or when, making incident detection and compliance impossible.

> **Note:** This check runs only in Live mode because it requires access to kube-system ConfigMaps.

**Remediation:**
Configure API server audit logging with a policy file and log backend. On managed clusters, enable audit logging through the cloud provider console:

```yaml
# kube-apiserver flags:
# --audit-policy-file=/etc/kubernetes/audit-policy.yaml
# --audit-log-path=/var/log/kubernetes/audit.log
# --audit-log-maxage=30
# --audit-log-maxbackup=10
# --audit-log-maxsize=100
```

---

### `admission-controllers`
**Severity:** Medium · **Modes:** Live only · **Auto-fix:** No

Detects when critical admission controllers (`NodeRestriction`, `PodSecurity`) are disabled via `--disable-admission-plugins`. The check inspects `kubeadm-config` and `kube-apiserver` ConfigMaps in `kube-system`. Disabling these controllers removes a defense-in-depth layer, allowing requests that would otherwise be rejected, such as privilege escalations or unsafe pod configurations.

> **Note:** This check runs only in Live mode because it requires access to kube-system ConfigMaps containing API server configuration.

**Remediation:**
Re-enable the admission controller in the API server configuration and restart the API server:

```yaml
# kube-apiserver flags:
# --enable-admission-plugins=NodeRestriction,PodSecurity,...
# Ensure critical controllers are NOT listed in:
# --disable-admission-plugins
```

---

### `etcd-encryption`
**Severity:** Critical · **Modes:** Live only · **Auto-fix:** No

Detects when etcd encryption is not configured by checking for the `--encryption-provider-config` flag in API server configuration. Without encryption at rest, all Kubernetes Secrets are stored as plaintext in etcd. Anyone with access to etcd backups, snapshots, or the etcd data directory can read every secret in the cluster, including database passwords, API keys, and TLS certificates.

> **Note:** This check runs only in Live mode because it requires access to kube-system ConfigMaps containing API server configuration.

**Remediation:**
Configure an EncryptionConfiguration and pass it to the API server. On managed clusters (EKS, GKE, AKS), enable KMS-backed envelope encryption through the provider console:

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

Then add `--encryption-provider-config=/path/to/config.yaml` to the API server flags.

---

### `kubelet-config`
**Severity:** High · **Modes:** Live only · **Auto-fix:** No

Detects kubelet misconfigurations by inspecting node status information. Currently flags nodes where the kubelet read-only port (10255) is open. This port serves pod specs, node metrics, and container information without any authentication, allowing attackers on the network to enumerate running workloads, discover environment variables, and map cluster topology.

> **Note:** This check runs only in Live mode because it requires access to Node status information.

**Remediation:**
Disable the read-only port in the kubelet configuration and use the authenticated kubelet API on port 10250 instead:

```yaml
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
readOnlyPort: 0
authentication:
  anonymous:
    enabled: false
  webhook:
    enabled: true
```

---

### `component-versions`
**Severity:** Medium · **Modes:** Live only · **Auto-fix:** No

Detects kubelet version skew exceeding the supported range. Kubernetes supports kubelets within 2 minor versions of the API server. The check compares kubelet versions across all nodes and flags any node more than 2 minor versions behind the newest. Nodes running older versions miss security patches, bug fixes, and may exhibit inconsistent behavior with newer API features.

> **Note:** This check runs only in Live mode because it reads kubelet version from Node status.

**Remediation:**
Upgrade the kubelet on outdated nodes to match the cluster version. Upgrade nodes in a rolling fashion, draining each node before upgrading:

```yaml
# For self-managed nodes:
# apt-get update && apt-get install -y \
#   kubelet=1.XX.Y-00 kubectl=1.XX.Y-00
# systemctl daemon-reload && systemctl restart kubelet

# For managed node pools (EKS/GKE/AKS):
# Update the node group/pool version in your cloud console
```

---

### `deprecated-api-usage`
**Severity:** Medium · **Modes:** Live, Manifest · **Auto-fix:** No

Detects resources using deprecated or removed API versions. Currently checks for `policy/v1beta1` PodSecurityPolicy resources, which were removed in Kubernetes 1.25. Deprecated APIs are removed in future Kubernetes versions, and manifests referencing them will fail during cluster upgrades, potentially causing outages.

**Remediation:**
Update the `apiVersion` field to the current stable API. Run `kubectl convert` or use tools like `kubent` to scan your entire codebase for deprecated API versions before upgrading:

```yaml
# Before (deprecated):
apiVersion: policy/v1beta1
kind: PodSecurityPolicy

# After (replacement):
# PodSecurityPolicy is removed in 1.25.
# Use Pod Security Admission instead:
apiVersion: v1
kind: Namespace
metadata:
  labels:
    pod-security.kubernetes.io/enforce: restricted
```
