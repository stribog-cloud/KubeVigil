# KubeVigil admission webhook

Manifests to run KubeVigil as a Kubernetes **ValidatingAdmissionWebhook**. The
webhook scans each admitted object with KubeVigil's checks (and any custom CEL
policies) and denies admission for findings at or above `--fail-on` severity,
surfacing the rest as admission warnings.

## Files

| File | Purpose |
|------|---------|
| `deployment.yaml` | Deployment + Service running `kubevigil webhook` (distroless, non-root) |
| `webhook-configuration.yaml` | `ValidatingWebhookConfiguration` wiring the API server to the service |

## TLS is required

The Kubernetes API server only calls webhooks over HTTPS, and it verifies the
serving certificate against the `caBundle` in the `ValidatingWebhookConfiguration`.
You must supply a serving certificate whose SAN matches
`kubevigil-webhook.kubevigil-system.svc`.

The simplest production path is [cert-manager](https://cert-manager.io): create a
`Certificate` for that DNS name into a `Secret` named `kubevigil-webhook-tls`,
and set the `ValidatingWebhookConfiguration`'s `caBundle` from the issuing CA
(cert-manager's `ca-injector` can populate it automatically via the
`cert-manager.io/inject-ca-from` annotation).

For a quick manual test, generate a self-signed cert:

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout tls.key -out tls.crt -days 365 \
  -subj "/CN=kubevigil-webhook.kubevigil-system.svc" \
  -addext "subjectAltName=DNS:kubevigil-webhook.kubevigil-system.svc"

kubectl create namespace kubevigil-system
kubectl -n kubevigil-system create secret tls kubevigil-webhook-tls --cert=tls.crt --key=tls.key
```

Then set `caBundle` in `webhook-configuration.yaml` to `base64 -w0 < tls.crt`.

## Safety notes

- The webhook **fails open**: if a scan errors internally or an object can't be
  decoded, the object is admitted with a warning rather than blocked. A webhook
  that fails closed on its own bugs is a cluster-wide outage.
- Scope the `ValidatingWebhookConfiguration`'s `rules` and `namespaceSelector`
  to start narrow (e.g. a single test namespace) before rolling out cluster-wide.
- `failurePolicy: Ignore` is set by default so an unavailable webhook never
  blocks admissions. Switch to `Fail` only once you trust its availability.

See `docs/integrations/admission-webhook.md` for the full guide.
