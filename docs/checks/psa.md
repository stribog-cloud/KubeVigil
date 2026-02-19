# Pod Security Standards Checks

KubeVigil includes 6 checks that inspect Pod Security Admission (PSA) configuration, Pod Security Standards (PSS) compliance, and PodSecurityPolicy migration status. These checks examine Namespaces, workload pod specs, and PodSecurityPolicy resources.

All PSA checks support both **Live** and **Manifest** scan modes.

---

## PSA Configuration

### `psa-labels-missing`
**Severity:** Medium · **Modes:** Live, Manifest · **Auto-fix:** Yes (Likely Safe)

Detects namespaces that lack the `pod-security.kubernetes.io/enforce` label. Without PSA enforcement labels, any pod configuration is allowed in the namespace, including privileged containers, host namespace access, and root execution. This bypasses Kubernetes' built-in Pod Security Standards. System namespaces are excluded from this check.

**Remediation:**
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

Start with `baseline` enforcement to block known privilege escalations, then upgrade to `restricted` after verifying all workloads are compliant.

**Frameworks:** CIS 5.2

---

### `psa-mode-audit-only`
**Severity:** Medium · **Modes:** Live, Manifest · **Auto-fix:** Yes (Likely Safe)

Detects namespaces with PSA labels set to audit or warn mode only, without the enforce label. In this configuration, violations are logged or shown as warnings but not blocked -- pods with security issues can still be admitted. The check only flags namespaces that have `audit` or `warn` labels but NOT the `enforce` label.

**Remediation:**
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

**Frameworks:** CIS 5.2

---

### `psa-version-pinning`
**Severity:** Low · **Modes:** Live, Manifest · **Auto-fix:** No

Detects namespaces where PSA version labels are pinned to a specific Kubernetes version (e.g., `v1.25`) rather than `latest`. Pinned versions do not automatically pick up new security restrictions when the cluster is upgraded, potentially leaving workloads exposed to newly-identified risks. The check inspects the version labels `pod-security.kubernetes.io/enforce-version`, `pod-security.kubernetes.io/audit-version`, and `pod-security.kubernetes.io/warn-version`. System namespaces are excluded.

**Remediation:**
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: my-namespace
  labels:
    pod-security.kubernetes.io/enforce-version: "latest"
```

If pinning is intentional (e.g., for compatibility testing), document the reason and plan to update after validation.

---

## PSS Compliance

### `psa-baseline-violations`
**Severity:** High · **Modes:** Live, Manifest · **Auto-fix:** No

Detects workloads that violate the Pod Security Standards (PSS) Baseline profile. The Baseline profile targets ease of adoption for common containerized workloads while preventing known privilege escalations. The check flags:

- `hostNetwork: true` -- gives the pod direct access to the node's network interfaces
- `hostPID: true` -- shares the host's process ID namespace
- `hostIPC: true` -- shares the host's IPC namespace
- `privileged: true` -- runs the container with full host privileges
- Dangerous capabilities (`ALL`, `SYS_ADMIN`) -- grants near-root privileges

**Remediation:**
```yaml
spec:
  hostNetwork: false
  hostPID: false
  hostIPC: false
  containers:
    - name: app
      securityContext:
        privileged: false
        capabilities:
          drop: [ALL]
          add: [NET_BIND_SERVICE]  # Only specific required caps
```

**Frameworks:** PSS Baseline, CIS 5.2.1-5.2.4

---

### `psa-restricted-violations`
**Severity:** Medium · **Modes:** Live, Manifest · **Auto-fix:** No

Detects workloads that violate the Pod Security Standards (PSS) Restricted profile additions beyond Baseline. The Restricted profile is the most hardened profile. This checker focuses on the Restricted-specific requirements:

- `runAsNonRoot` must be explicitly `true` at the container or pod level
- `allowPrivilegeEscalation` must be explicitly `false`
- `capabilities.drop` must include `ALL`

The check evaluates both container-level and pod-level security contexts with proper inheritance for `runAsNonRoot`.

**Remediation:**
```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
  allowPrivilegeEscalation: false
  capabilities:
    drop: [ALL]
    add: [NET_BIND_SERVICE]  # Only if binding to ports below 1024
```

Set `runAsNonRoot` at the pod level to apply to all containers.

**Frameworks:** PSS Restricted, CIS 5.2.5-5.2.7

---

## PSP Migration

### `psp-still-present`
**Severity:** Info · **Modes:** Live, Manifest · **Auto-fix:** No

Detects deprecated PodSecurityPolicy (PSP) resources that are still present in the cluster. PSP was deprecated in Kubernetes 1.21 and fully removed in 1.25. Lingering PSP resources indicate an incomplete migration to Pod Security Admission (PSA). On clusters running 1.25+, PSPs have no effect and provide zero security protection.

**Remediation:**
```yaml
apiVersion: v1
kind: Namespace
metadata:
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

After verifying PSA enforcement is active on all namespaces, remove PSP resources with `kubectl delete psp <name>`.
