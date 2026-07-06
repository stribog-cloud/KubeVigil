# CRD Security Checks

KubeVigil includes 7 checks covering CustomResourceDefinition security and cert-manager certificate management, detecting unvalidated CRDs, conversion webhook risks, certificate expiry, weak cryptographic configurations, and CRD schema/subresource hardening gaps.

## Checks

### `crd-validation-missing`
**Severity:** Medium · **Modes:** Live, Manifest · **Auto-fix:** No

Detects CustomResourceDefinitions without an OpenAPI validation schema. CRDs without validation accept any arbitrary input, allowing attackers or misconfigured automation to create custom resources with malicious fields, causing controller crashes, injection attacks, or unexpected behavior in operators that trust the data.

**Remediation:**
Add an OpenAPI v3 validation schema to each version in the CRD spec. Use `x-kubernetes-validations` for CEL-based custom validation rules in Kubernetes 1.25+:

```yaml
spec:
  versions:
    - name: v1
      schema:
        openAPIV3Schema:
          type: object
          properties:
            spec:
              type: object
              required: [replicas]
              properties:
                replicas:
                  type: integer
                  minimum: 1
                  maximum: 100
```

---

### `crd-conversion-webhook`
**Severity:** High · **Modes:** Live, Manifest · **Auto-fix:** No

Detects CRDs with conversion webhooks that could be compromised to manipulate data during API version conversion. The check flags two scenarios: webhooks using an external URL (vulnerable to DNS hijacking, man-in-the-middle attacks, and external service outages) and webhooks using an in-cluster service reference (a compromised webhook can silently modify data during conversions).

**Remediation:**
If using an external URL, replace it with an in-cluster service reference. For in-cluster webhooks, ensure the service is properly secured with TLS (preferably via cert-manager), restrict access via NetworkPolicy, and limit RBAC permissions for modifying the webhook service:

```yaml
spec:
  conversion:
    strategy: Webhook
    webhook:
      clientConfig:
        service:
          name: my-webhook-svc
          namespace: my-system
          path: /convert
        caBundle: <base64-ca-cert>
---
# Restrict network access to the webhook:
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: webhook-access
spec:
  podSelector:
    matchLabels:
      app: my-webhook
  ingress:
    - from:
        - namespaceSelector: {}
      ports:
        - port: 443
```

---

### `cert-manager-expiry`
**Severity:** High · **Modes:** Live only · **Auto-fix:** No

Detects cert-manager Certificate resources that are nearing expiry (within 14 days), have already expired, or are in a failed renewal state. Expired certificates cause immediate TLS handshake failures for all clients, and certificates stuck in a failed renewal state will not be renewed automatically.

> **Note:** This check runs only in Live mode because it relies on Certificate status fields (`status.notAfter`, `status.conditions`) which are populated by the cert-manager controller at runtime.

**Remediation:**
For expired or nearly expired certificates, trigger an immediate manual renewal. For failed renewals, diagnose the underlying issue:

```bash
# Force renewal using cert-manager CLI:
kubectl cert-manager renew <certificate-name> -n <namespace>

# Or delete the Secret to trigger re-issuance:
kubectl delete secret <cert-secret-name> -n <namespace>

# Check Certificate status and events:
kubectl describe certificate <name> -n <namespace>

# Check cert-manager controller logs:
kubectl logs -n cert-manager deploy/cert-manager
```

Configure `renewBefore` to ensure certificates are renewed well before expiry:

```yaml
spec:
  duration: 2160h               # 90 days
  renewBefore: 720h             # Renew 30 days before expiry
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
```

---

### `cert-manager-insecure`
**Severity:** Medium · **Modes:** Live, Manifest · **Auto-fix:** No

Detects cert-manager Certificate resources using weak key algorithms or excessively long durations. The check flags: RSA keys smaller than 2048 bits (can be factored with modern hardware), ECDSA keys smaller than P-256 (below 128-bit security equivalent), and certificate durations longer than 1 year (8760 hours), which increase the window of exposure if a private key is compromised.

**Remediation:**
Use strong key algorithms and short-lived certificates. For RSA, use at least 2048 bits (4096 preferred). For ECDSA, use P-256 minimum. Reduce certificate duration to 90 days or less:

```yaml
spec:
  duration: 2160h               # 90 days
  renewBefore: 720h             # Renew 30 days before expiry
  privateKey:
    algorithm: ECDSA
    size: 256                   # P-256 (128-bit security)
    rotationPolicy: Always      # New key on each renewal
```

For RSA:

```yaml
spec:
  privateKey:
    algorithm: RSA
    size: 4096                  # Minimum 2048, prefer 4096
    rotationPolicy: Always
```

---

### `crd-preserve-unknown-fields`
**Severity:** Medium · **Modes:** Live, Manifest · **Auto-fix:** No

Detects CustomResourceDefinitions with the deprecated top-level `spec.preserveUnknownFields: true`, which disables structural-schema pruning entirely for the CRD. Any client can write arbitrary, unvalidated fields into every version of the custom resource, defeating the guarantees a structural OpenAPI schema is supposed to provide and enabling injection into fields controllers may not expect or sanitize.

**Remediation:**
```yaml
spec:
  preserveUnknownFields: false
  versions:
    - name: v1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          properties:
            spec:
              type: object
```

Test existing custom resources against the new schema before rolling out -- previously-valid resources relying on unknown fields may be rejected once pruning is enabled.

---

### `crd-status-subresource-missing`
**Severity:** Medium · **Modes:** Live, Manifest · **Auto-fix:** No

Detects CRD versions whose schema defines a `status` object but do not enable `subresources.status`. Without the status subresource, there is only one write endpoint for the custom resource -- any client with permission to update the resource's `spec` can also arbitrarily overwrite its `status`. Controllers frequently treat `status` as authoritative state they alone should write; without the subresource split, application clients can corrupt that state, breaking the spec/status separation Kubernetes controllers rely on for correctness.

**Remediation:**
```yaml
spec:
  versions:
    - name: v1
      served: true
      storage: true
      subresources:
        status: {}
      schema:
        openAPIV3Schema:
          type: object
          properties:
            spec:
              type: object
            status:
              type: object
```

Update controller RBAC to grant `update`/`patch` on the `<resource>/status` subresource separately from the main resource.

---

### `crd-multiversion-no-conversion`
**Severity:** Medium · **Modes:** Live, Manifest · **Auto-fix:** No

Detects CRDs serving 2+ versions (`served: true` on multiple entries) with no conversion webhook configured (`spec.conversion.strategy` absent or `None`). Without a real conversion webhook, Kubernetes falls back to the trivial `None` conversion strategy, which copies fields byte-for-byte between versions with no actual transformation -- any field that differs in shape or name between versions silently round-trips as data loss or a zeroed value. Distinct from `crd-conversion-webhook`, which only inspects webhooks that already exist; this flags CRDs that need one but don't have it.

**Remediation:**
```yaml
spec:
  conversion:
    strategy: Webhook
    webhook:
      clientConfig:
        service:
          name: my-crd-converter
          namespace: my-system
          path: /convert
        caBundle: <base64-ca-cert>
```

If only one version needs to remain served long-term, consider deprecating and removing the older served version instead of maintaining lossy multi-version support.
