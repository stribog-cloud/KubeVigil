# Secrets Management Checks

KubeVigil includes 12 checks that inspect how secrets are stored, referenced, rotated, and managed across your cluster. These checks examine Secrets, ConfigMaps, workload pod specs (including annotations/labels and `envFrom`), and ExternalSecret custom resources.

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

### `secrets-envfrom-bulk`
**Severity:** High · **Modes:** Live, Manifest · **Auto-fix:** No

Detects containers using `envFrom[].secretRef` to bulk-inject **every** key in a Secret as environment variables. Strictly worse than the per-key `secrets-in-env` case: a single misconfiguration here exposes the Secret's entire contents to process listings (`/proc/*/environ`), crash dumps, log output, and any child process the container spawns, not just one key.

**Remediation:**
```yaml
volumeMounts:
  - name: secret-vol
    mountPath: /etc/secrets
    readOnly: true
volumes:
  - name: secret-vol
    secret:
      secretName: db-credentials
```

If environment variables are required, reference individual keys explicitly instead of the whole Secret:
```yaml
env:
  - name: DB_PASSWORD
    valueFrom:
      secretKeyRef:
        name: db-credentials
        key: password
```

**Frameworks:** CIS 5.4.1

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

### `secrets-in-annotations`
**Severity:** High · **Modes:** Live, Manifest · **Auto-fix:** No

Detects workload resources (Deployments, Pods, and other workload kinds) with secret-looking values -- API keys, tokens, high-entropy strings -- embedded directly in `metadata.annotations` or `metadata.labels`. Annotations and labels are readable by anyone with `get`/`list` RBAC on the resource type, typically far broader than the RBAC applied to the `secrets` resource -- a credential here is exposed to every user, CI job, or controller that can read Deployments, entirely bypassing tighter Secret-specific access controls. Uses the same entropy-analysis and known-pattern-matching technique already proven by `secrets-in-configmap`.

**Remediation:**
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-secret
type: Opaque
stringData:
  api-key: "<managed-externally>"
```

Rotate any credential that was previously committed to an annotation or label, since it may already be cached by API clients, audit logs, or GitOps tooling that snapshots object metadata.

**Frameworks:** CIS 5.4.1, MITRE T1552

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

### `secrets-immutable-missing`
**Severity:** Low · **Modes:** Live, Manifest · **Auto-fix:** No

Detects Secret resources without `immutable: true`. Without it, a Secret's data can be modified in place by anyone with update access, whether accidentally or maliciously. Mutable Secrets also increase load on the API server, since every kubelet watching the Secret must be notified and re-sync on every change.

**Remediation:**
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-secret
immutable: true
type: Opaque
data:
  password: <base64-value>
```

Immutable Secrets must be deleted and recreated (or replaced under a new name) to rotate their contents, which pairs naturally with GitOps and templated Secret names.

---

### `serviceaccount-token-secret-legacy`
**Severity:** Medium · **Modes:** Live, Manifest · **Auto-fix:** No

Detects Secret resources of type `kubernetes.io/service-account-token`. Since Kubernetes 1.24, these are no longer auto-created per ServiceAccount; their presence indicates a legacy, manually created, non-expiring token -- unlike the bound, audience-scoped, auto-rotating tokens issued via the TokenRequest API and projected volumes. A leaked legacy token remains valid indefinitely until manually revoked. Distinct from `secrets-stale` (rotation staleness of any Secret) and `token-projection-config` (RBAC, live pod-level configuration): this flags the legacy Secret **object's existence** itself.

**Remediation:**
```yaml
spec:
  serviceAccountName: my-app
  automountServiceAccountToken: true  # default projected volume token
```

Once no workload depends on the legacy Secret, delete it. Verify no controller reads it directly before removal -- deleting a token still in use will break authentication for anything relying on it.

**Frameworks:** MITRE T1528, NSA/CISA 3.1

---

### `secrets-tls-weak-key`
**Severity:** Medium · **Modes:** Live, Manifest · **Auto-fix:** No

Detects raw `kubernetes.io/tls` Secrets -- not managed by cert-manager -- whose certificate uses a weak key: RSA smaller than 2048 bits, or an ECDSA curve weaker than P-256. Weak keys can be factored or attacked with modern hardware, allowing an adversary to forge certificates and intercept or impersonate encrypted TLS connections. Applies the same key-strength logic already established by `cert-manager-insecure`, but to statically-created TLS Secrets that cert-manager never touches.

**Remediation:**
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-tls-secret
type: kubernetes.io/tls
data:
  tls.crt: <base64 cert, RSA >= 2048 or ECDSA P-256+>
  tls.key: <base64 key>
```

Consider adopting cert-manager to automate issuance and renewal with a compliant key configuration going forward.

**Frameworks:** CIS 5.4.1

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
