# CRD Security Checks

KubeVigil includes 4 checks covering CustomResourceDefinition security and cert-manager certificate management, detecting unvalidated CRDs, conversion webhook risks, certificate expiry, and weak cryptographic configurations.

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
