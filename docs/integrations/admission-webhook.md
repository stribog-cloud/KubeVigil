# Admission Webhook

`kubevigil webhook` runs KubeVigil as a Kubernetes **ValidatingAdmissionWebhook**. Instead of scanning on a schedule or in CI, it scans every object at the moment the API server admits it -- `CREATE` and `UPDATE` -- and can deny the request outright when what's being admitted is dangerous enough. It runs the same 110 built-in checks (and any custom CEL policies you've configured) that `kubevigil scan` uses, through the identical post-processing pipeline (severity overrides, exemptions, framework attachment), so a webhook verdict is never surprising relative to what a manifest scan of that one object would have reported.

## How it works: deny, warn, or allow

Every admission request produces exactly one of three outcomes, decided by comparing each finding's severity against the `--fail-on` threshold (default `high`):

| Finding severity vs. `--fail-on` | Outcome |
|---|---|
| At or above the threshold | Request is **denied** (HTTP 403) |
| Below the threshold | Request is **allowed**, finding surfaces as an admission **warning** |
| No findings | Request is **allowed**, no warnings |

Severity is ordinal: **Info** < **Low** < **Medium** < **High** < **Critical**. With the default `--fail-on=high`, **High** and **Critical** findings deny; **Medium**, **Low**, and **Info** findings become warnings but never block the request. Setting `--fail-on=critical` narrows denials to only **Critical** findings; setting `--fail-on=info` denies on any finding at all.

A denial and its warnings are not mutually exclusive: if an object has both a **Critical** and a **Medium** finding, the request is denied *and* the **Medium** finding still rides along as a warning in the same response -- nothing about the object's posture is silently dropped just because the request was already going to be rejected.

Every warning message is prefixed `kubevigil: ` so operators can tell KubeVigil's warnings apart from other admission controllers' in `kubectl` output and audit logs.

### Fail-open by design

The webhook is deliberately **fail-open** in two situations, both allowing the request through rather than blocking it:

- **The object can't be decoded**, or is missing `apiVersion`/`kind` entirely -- the request is allowed with a single warning (`kubevigil: could not decode object; allowed without scanning`) and no scan is attempted.
- **The scan itself errors** (a checker panic recovery, a CEL evaluation error, an unresolvable GVR, etc.) -- the request is allowed with a warning describing the error, and the failure is also logged server-side at `warn` level.

This is intentional, not an oversight: a validating webhook that fails **closed** on its own internal bugs turns a KubeVigil defect into a cluster-wide outage -- nothing matching the webhook's rules could be created or updated until someone diagnosed and fixed (or removed) the webhook. Fail-open trades a missed detection for availability. If you need stronger guarantees than fail-open provides, pair the webhook with scheduled `kubevigil scan` runs (CI or a cron `Job`) as a backstop that will still catch anything the webhook missed or was down for.

## Quick start: run it locally

You don't need a cluster to try the webhook -- it's a plain HTTPS server you can drive with `curl`.

Build the binary and generate a throwaway self-signed certificate:

```bash
make build

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout /tmp/k.key -out /tmp/k.crt -days 1 \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost"
```

Start the webhook:

```bash
./bin/kubevigil webhook --addr=127.0.0.1:18543 --tls-cert=/tmp/k.crt --tls-key=/tmp/k.key --fail-on=high &
```

Confirm it's up:

```bash
curl -sk https://127.0.0.1:18543/healthz
# ok
```

POST an `AdmissionReview` at the configured `--path` (default `/validate`). Below are two real captures from a running instance.

### A denied request

A `Pod` with a privileged container triggers `privileged` (**Critical**), well above the default `--fail-on=high` threshold, alongside several **High** findings:

```bash
curl -sk -X POST https://127.0.0.1:18543/validate \
  -H "Content-Type: application/json" \
  --data '{
    "apiVersion": "admission.k8s.io/v1",
    "kind": "AdmissionReview",
    "request": {
      "uid": "3f9b1e2a-1234-4d5e-8a9b-abcdef012345",
      "object": {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "web-privileged", "namespace": "default"},
        "spec": {"containers": [{"name": "app", "image": "nginx:latest",
          "securityContext": {"privileged": true}}]}
      }
    }
  }'
```

Response (trimmed to a few warnings for readability -- the real response also included resource-limits, capability, and PSA-baseline warnings):

```json
{
  "kind": "AdmissionReview",
  "apiVersion": "admission.k8s.io/v1",
  "response": {
    "uid": "3f9b1e2a-1234-4d5e-8a9b-abcdef012345",
    "allowed": false,
    "status": {
      "metadata": {},
      "message": "kubevigil denied admission: 6 finding(s) at or above High severity:\n  - [Critical] privileged (default/web-privileged): Container \"app\" is running in privileged mode, granting full host access.\n  - [High] privilege-escalation (default/web-privileged): Container \"app\" does not set allowPrivilegeEscalation to false, permitting privilege escalation.\n  - [High] run-as-root (default/web-privileged): Container \"app\" does not set runAsNonRoot: true and may run as root.\n  - [High] automount-token (default/web-privileged): Pod \"web-privileged\" auto-mounts a ServiceAccount token. Most workloads do not need Kubernetes API access.\n  - [High] default-service-account (default/web-privileged): Pod \"web-privileged\" uses the default ServiceAccount, which may have unintended permissions.\n  - [High] psa-baseline-violations (default/web-privileged): Pod \"web-privileged\" container \"app\" violates PSS Baseline: privileged is true.",
      "reason": "Forbidden",
      "code": 403
    },
    "warnings": [
      "kubevigil: [Medium] resource-limits-missing (default/web-privileged): Container \"app\" is missing both CPU and memory limits.",
      "kubevigil: [Medium] capabilities-not-dropped (default/web-privileged): Container \"app\" does not drop ALL capabilities, leaving it with unnecessary default privileges.",
      "kubevigil: [Medium] image-tag-latest (default/web-privileged): Container \"app\" uses the :latest tag (image: nginx:latest), which can lead to unpredictable deployments."
    ]
  }
}
```

Note that the denial `message` lives under `status`, not a top-level `message` -- the `AdmissionResponse.Result` field is a Kubernetes `Status` object, which serializes its human-readable text as `status.message`. Anything that renders admission errors (kubectl, a controller, an audit log processor) reads it from there.

### An allowed request with warnings

The same shape of `Pod`, hardened with `runAsNonRoot`, dropped capabilities, a read-only root filesystem, resource limits, probes, and a non-default `serviceAccountName`, produces no denying findings -- only low-signal warnings:

```json
{
  "kind": "AdmissionReview",
  "apiVersion": "admission.k8s.io/v1",
  "response": {
    "uid": "7a2c4e1b-9988-4a1c-b0de-fedcba987654",
    "allowed": true,
    "warnings": [
      "kubevigil: [Low] run-as-high-uid (payments/web-hardened): Container \"app\" runs as UID 1000, which is below the recommended minimum of 10000.",
      "kubevigil: [Low] runtime-class (payments/web-hardened): Pod \"web-hardened\" does not specify a RuntimeClass, using the default (unsandboxed) runtime.",
      "kubevigil: [Medium] apparmor-profile (payments/web-hardened): Container \"app\" does not have an AppArmor profile set.",
      "kubevigil: [Low] resource-limits-ratio (payments/web-hardened): Container \"app\" has high limits-to-requests ratio for CPU (5.0x), threshold is 3.0x.",
      "kubevigil: [Low] topology-spread (payments/web-hardened): Pod \"web-hardened\" has no topology spread constraints; all replicas may be scheduled on the same node.",
      "kubevigil: [Low] priority-class-missing (payments/web-hardened): Pod \"web-hardened\" has no PriorityClass set; it will be evicted first during resource pressure.",
      "kubevigil: [Info] startup-probes (payments/web-hardened): Container \"app\" has a liveness probe but no startup probe, which can cause restart loops during slow startup."
    ]
  }
}
```

There's no `status` key at all when `allowed` is `true` and nothing was denied -- `warnings` is the only thing riding along.

## TLS requirements

The Kubernetes API server only ever calls webhooks over HTTPS, and it verifies the serving certificate's chain against the `caBundle` configured in the `ValidatingWebhookConfiguration`. `kubevigil webhook` refuses to start without `--tls-cert` and `--tls-key` -- there is no insecure/plaintext mode.

The certificate's Subject Alternative Name **must** match the in-cluster DNS name of the `Service` fronting the webhook -- for the manifests in `deploy/webhook/`, that's `kubevigil-webhook.kubevigil-system.svc`. A SAN mismatch causes the API server to reject the TLS handshake, which (combined with `failurePolicy: Ignore`, the shipped default) silently allows every matching admission through unchecked -- so a SAN mismatch is easy to miss and worth checking first if the webhook seems to have no effect.

Two ways to get that certificate:

- **cert-manager** (recommended for anything beyond a quick test): create a `Certificate` resource for `kubevigil-webhook.kubevigil-system.svc`, targeting a `Secret` named `kubevigil-webhook-tls`. Annotate the `ValidatingWebhookConfiguration` with `cert-manager.io/inject-ca-from: kubevigil-system/kubevigil-webhook` and cert-manager's `ca-injector` populates `caBundle` for you automatically -- including on renewal, so you never hand-manage the CA bundle.
- **Manual self-signed** (fine for local testing, not recommended long-term because you own rotation yourself):

  ```bash
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout tls.key -out tls.crt -days 365 \
    -subj "/CN=kubevigil-webhook.kubevigil-system.svc" \
    -addext "subjectAltName=DNS:kubevigil-webhook.kubevigil-system.svc"

  kubectl create namespace kubevigil-system
  kubectl -n kubevigil-system create secret tls kubevigil-webhook-tls --cert=tls.crt --key=tls.key
  ```

  Then set `caBundle` in `webhook-configuration.yaml` to `base64 -w0 < tls.crt`.

## Deployment walkthrough

The manifests live in `deploy/webhook/`: `deployment.yaml` (Namespace, Deployment, Service) and `webhook-configuration.yaml` (the `ValidatingWebhookConfiguration`). Apply order matters because the Deployment's pods mount the TLS secret as a volume and won't start without it:

1. **Namespace**, if not already applying `deployment.yaml` for it: `kubectl create namespace kubevigil-system`.
2. **TLS secret** -- via cert-manager's `Certificate`, or the manual `kubectl create secret tls` above. Must exist before the Deployment's pods are scheduled.
3. **Deployment + Service**:

   ```bash
   kubectl apply -f deploy/webhook/deployment.yaml
   ```

   This runs 2 replicas of the distroless, non-root (`runAsUser: 65532`), read-only-rootfs container, with liveness/readiness probes against `/healthz` and `capabilities.drop: ["ALL"]`. Pin the image tag to a release (e.g. `ghcr.io/stribog-cloud/kubevigil:1.2.0`) before this goes anywhere near production -- the shipped manifest defaults to `:latest`.

4. **caBundle** -- fill in `webhook-configuration.yaml`'s `caBundle: REPLACE_WITH_BASE64_CA_BUNDLE` with `base64 -w0 < tls.crt` (manual path), or rely on the cert-manager `ca-injector` annotation if you went that route.
5. **ValidatingWebhookConfiguration**:

   ```bash
   kubectl apply -f deploy/webhook/webhook-configuration.yaml
   ```

6. **Verify**: create a pod that should be denied (e.g. one with `securityContext.privileged: true`) in a namespace the `namespaceSelector` covers, and confirm `kubectl` reports the denial. See [Safe rollout](#safe-rollout) below before doing this cluster-wide.

## `ValidatingWebhookConfiguration` knobs

The shipped `webhook-configuration.yaml` is a reasonable, narrowed-by-default starting point -- read through its knobs before widening anything:

| Field | Shipped default | What it controls |
|---|---|---|
| `rules[].apiGroups` / `apiVersions` | `["", "apps", "batch"]` / `["v1"]` | Which API groups the webhook is invoked for |
| `rules[].resources` | `pods, deployments, statefulsets, daemonsets, replicasets, jobs, cronjobs` | Which resource types are scanned. Adding a resource here is the only way KubeVigil ever sees it at admission time |
| `rules[].operations` | `["CREATE", "UPDATE"]` | The webhook is not invoked on `DELETE` -- there's nothing to scan in a deletion |
| `rules[].scope` | `Namespaced` | Cluster-scoped resources (e.g. `Namespace` itself) are out of scope for this webhook |
| `namespaceSelector` | excludes `kube-system`, `kube-public`, `kube-node-lease`, `kubevigil-system` | Narrows which namespaces the webhook fires in. **This is the primary lever for a safe rollout** -- see below |
| `failurePolicy` | `Ignore` | `Ignore`: an unreachable/erroring webhook allows the request through (availability over enforcement). `Fail`: an unreachable webhook **blocks** every matching admission cluster-wide. Only switch to `Fail` once you trust the webhook's uptime -- with `Fail`, a webhook outage becomes an outage for every workload the rules match |
| `timeoutSeconds` | `10` | The API server's total budget for the webhook call, including network round-trip. Must stay comfortably above `--scan-timeout` (see [Tuning](#tuning---fail-on-and---scan-timeout)) or the API server will time out the call itself, which is treated per `failurePolicy` just like any other webhook failure |
| `admissionReviewVersions` | `["v1"]` | The webhook only speaks `AdmissionReview` `v1` (`admission.k8s.io/v1`) -- confirmed by the handler, which rejects anything it can't decode as that type |
| `sideEffects` | `None` | Declares the webhook makes no changes outside the admission response itself (it doesn't mutate objects or call out to other systems) -- required for `kubectl --dry-run` to work correctly against admission chains that include this webhook |

Excluding `kubevigil-system` itself from `namespaceSelector` avoids the awkward case of the webhook's own Deployment update being evaluated by the webhook.

## Custom CEL policies at admission

`customPolicies:` entries in `.kubevigil.yaml` are compiled into checkers and registered exactly like the 110 built-in checks, so they run at admission time too -- the same policy that flags a resource in `kubevigil scan` will flag it (and can deny it) in the webhook, with no separate authoring step. The webhook loads config the same way `scan` and `fix` do: an explicit `--config` path if given, otherwise auto-discovery of `.kubevigil.yaml`, falling back to defaults if neither is found.

One difference from `scan`: **`kubevigil webhook` has no `--policy-file` flag.** That flag only exists on `kubevigil scan`. To run custom policies at admission, put them in `customPolicies:` inside the config the webhook loads -- there's no equivalent of pointing the webhook at a standalone policy file or directory per invocation. See [Custom Policies](../policies/custom-policies.md) for the policy schema and CEL environment.

## Tuning `--fail-on` and `--scan-timeout`

- **`--fail-on`** (default `high`): the minimum severity that denies admission. Teams new to the webhook often start at `critical` (deny only the most severe findings) while they get used to seeing warnings for everything else, then tighten to `high` or lower once noise is under control. `--fail-on info` denies on *any* finding -- useful for a locked-down namespace, punishing everywhere else.
- **`--scan-timeout`** (default `5s`): bounds a single object's scan. If it's exceeded, the scan is cancelled and treated as a scan error -- which, per the fail-open design above, allows the request with a warning rather than denying it. Keep `--scan-timeout` meaningfully below the `ValidatingWebhookConfiguration`'s `timeoutSeconds` (`10s` shipped) so the webhook can time out its own scan and still return a normal response, instead of the API server timing out the whole call first.

## Observability

- **`/healthz`** -- an unauthenticated `GET` returning `200 ok`, served alongside `--path` on the same HTTPS listener. It's not configurable via a flag; it's always `/healthz`. The shipped `deployment.yaml` wires both the liveness and readiness probes to it.
- **Warnings in `kubectl` output** -- every `kubevigil:`-prefixed warning the API server returns is rendered by `kubectl` as a `Warning:` line above the normal command output (e.g. `pod/web created`), whether the request was allowed or (alongside the denial message) rejected. This is standard Kubernetes admission-warning behavior, not anything KubeVigil does specially -- it's why every message is prefixed, so operators can immediately tell a KubeVigil warning apart from another webhook's or the API server's own.
- **Server-side logs** -- scan errors are logged at `warn` level with the object's kind and name (`slog.Warn("admission scan error; allowing", ...)`); the response-encoding failure path logs at `error` level. Run with the global `--verbose` flag for debug-level logging, including the startup line reporting the listen address, path, and configured `--fail-on`.

## Safe rollout

Rolling out a validating webhook cluster-wide on day one risks blocking (or, with `failurePolicy: Ignore`, silently no-op'ing for) every matching workload at once. A narrower path:

1. **Start narrow.** Restrict `namespaceSelector` to a single canary or test namespace (label it and match on that label) rather than the shipped "every namespace except system ones" default. Nothing outside that namespace is affected while you validate behavior.
2. **Keep `failurePolicy: Ignore`.** This is already the shipped default -- an unavailable or erroring webhook allows admissions through rather than blocking them. Don't flip this to `Fail` until later.
3. **Watch.** Create and update real workloads in the canary namespace. Confirm expected objects are denied or warned as intended, watch `kubectl` output for `kubevigil:` warnings, and check the Deployment's logs and `/healthz` for stability under real traffic.
4. **Widen gradually.** Expand `namespaceSelector` to more namespaces (or move to the shipped "all but system namespaces" default) once you're confident in the false-positive rate and the webhook's availability.
5. **Consider `failurePolicy: Fail` last, deliberately.** Only after you trust the webhook's uptime (2 replicas, healthy probes, acceptable `--scan-timeout` headroom under `timeoutSeconds`) -- and only if you actually want a webhook outage to block admissions rather than let them through. This is a real availability-vs-enforcement trade-off, not a "more secure = always better" setting; most teams are well served staying on `Ignore` indefinitely.

## See Also

- [Custom Policies](../policies/custom-policies.md) -- CEL policy schema and environment, also enforced at admission
- [CLI Reference: `kubevigil webhook`](../reference/cli-reference.md#kubevigil-webhook) -- all flags and exit codes
- [Configuration File](../configuration/config-file.md) -- `.kubevigil.yaml` schema, including `customPolicies:`
- `deploy/webhook/` -- the Deployment, Service, and `ValidatingWebhookConfiguration` manifests referenced throughout this guide
