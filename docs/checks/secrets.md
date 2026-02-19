# Secrets Management Checks

KubeVigil includes 7 checks that inspect how secrets are stored, referenced, rotated, and managed across your cluster. These checks examine Secrets, ConfigMaps, workload pod specs, and ExternalSecret custom resources.

Most secrets checks support both Live and Manifest modes, with a few mode-specific exceptions noted below.

---

## Secret References

### `secrets-in-env`
**Severity:** Medium · **Modes:** Live, Manifest · **Auto-fix:** No

Detects containers that pass secrets via environment variables using `env[].valueFrom.secretKeyRef` instead of volume mounts. Environment variables are visible in pod specs, process listings (`/proc/*/environ`), crash dumps, and log output. They are also inherited by child processes. File-mounted secrets are stored on tmpfs, are not exposed in logs or process listings, and support automatic rotation via the kubelet.

**Remediation:**
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

**Frameworks:** CIS 5.4.1, NSA/CISA

---

### `secrets-in-configmap`
**Severity:** High · **Modes:** Live, Manifest · **Auto-fix:** No

Detects ConfigMaps containing values that look like secrets. ConfigMaps are not encrypted at rest and have weaker RBAC defaults than Secrets. Any user with namespace read access can view ConfigMap data. The check uses three detection strategies: key name matching (e.g., keys containing `password`, `token`, `secret`), known pattern matching (e.g., JWT tokens, AWS keys), and Shannon entropy analysis for high-entropy values that may be credentials.

**Remediation:**
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

**Frameworks:** CIS 5.4.1

---

### `secrets-hardcoded-manifests`
**Severity:** High · **Modes:** Manifest · **Auto-fix:** No

Detects hardcoded secret values in Kubernetes Secret manifests that appear to be real credentials. When secrets are committed to version control with real values, they become available to anyone with repository access. The check analyzes both `.data` (base64-encoded) and `.stringData` (plaintext) fields using known pattern matching and entropy analysis. This check is **Manifest only** -- in live mode, values are already stored in etcd; this check targets source manifests before they are applied.

**Remediation:**
```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: my-secret
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: SecretStore
  target:
    name: my-secret
```

Rotate any credential that was previously committed. Consider Sealed Secrets, SOPS, Vault Agent, or cloud-native secret managers as alternatives.

**Frameworks:** CIS 5.4.2

---

## Secret Storage

### `secrets-unencrypted`
**Severity:** Critical · **Modes:** Live · **Auto-fix:** No

Detects when the cluster may not have encryption at rest configured for Secrets. By default, Kubernetes stores Secrets as base64-encoded plaintext in etcd. Anyone with direct etcd access or an etcd backup can read every secret in the cluster. This is a heuristic check since EncryptionConfiguration is not directly queryable via the standard Kubernetes API. The check skips managed Kubernetes services (EKS, GKE, AKS) where encryption at rest is managed by the cloud provider. This check is **Live only** -- encryption at rest is not detectable from manifests.

**Remediation:**
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

**Frameworks:** CIS 1.2.29

---

### `secrets-default-type`
**Severity:** Low · **Modes:** Live, Manifest · **Auto-fix:** No

Detects Secrets using the Opaque type where a more specific built-in Secret type would be appropriate based on the data keys. Kubernetes provides typed Secrets (e.g., `kubernetes.io/tls`, `kubernetes.io/basic-auth`) that enforce required key names and enable automatic validation. Using the generic Opaque type bypasses these guardrails.

**Remediation:**
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-secret
type: kubernetes.io/tls    # Use the specific type
```

Kubernetes will validate that the required data keys are present for the chosen type.

---

## Secret Rotation

### `secrets-stale`
**Severity:** Medium · **Modes:** Live · **Auto-fix:** No

Detects Secrets that have not been rotated within a configurable period. Long-lived secrets increase the blast radius of a compromise. If a credential is leaked, the exposure window equals the time since the last rotation. The check evaluates the `kubevigil.io/last-rotated` annotation first, then falls back to the creation timestamp. Service account tokens and secrets in `kube-system` are excluded. This check is **Live only** -- manifests do not have reliable timestamps.

The rotation period is configurable via `policies.secrets.maxAgeDays` in `.kubevigil.yaml`.

**Remediation:**
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-secret
  annotations:
    kubevigil.io/last-rotated: "2025-01-15T00:00:00Z"
type: Opaque
stringData:
  password: "<new-rotated-value>"
```

Automate rotation using Vault dynamic secrets, AWS Secrets Manager rotation lambdas, or the External Secrets Operator's rotation features.

**Frameworks:** NIST SP 800-63B, CIS

---

## External Secrets

### `external-secrets-sync`
**Severity:** Medium · **Modes:** Live · **Auto-fix:** No

When the ExternalSecrets operator is present, checks for sync failures, missing SecretStore references, or stale externally-managed secrets. A sync failure means the target Kubernetes Secret is not being updated from the external secret provider, so workloads may be using expired or revoked credentials. The check also verifies that the referenced SecretStore or ClusterSecretStore exists. This check is **Live only** -- ExternalSecret status is only available at runtime.

**Remediation:**
```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: my-secret
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: my-store
    kind: SecretStore
  target:
    name: my-secret
```

Run `kubectl describe externalsecret <name> -n <namespace>` and check operator pod logs to diagnose sync issues.
