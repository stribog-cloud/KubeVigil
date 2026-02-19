# Exemptions

Exemptions allow you to suppress specific findings for resources that have been reviewed and accepted. KubeVigil supports two exemption mechanisms: configuration-based exemptions in `.kubevigil.yaml` and annotation-based exemptions directly on Kubernetes resources.

## Configuration-Based Exemptions

Configuration-based exemptions are defined in the `exemptions` section of your `.kubevigil.yaml` file. They are ideal for broad exemptions that apply across resources, such as skipping all checks for an entire namespace.

### Syntax

```yaml
exemptions:
  - namespace: <namespace>         # Optional: limit to this namespace
    resource: <resource-name>      # Optional: limit to this resource name
    kind: <resource-kind>          # Optional: limit to this resource kind
    checks:                        # Optional: limit to these check IDs (empty = all)
      - <check-id>
    reason: <reason>               # Recommended: why this exemption exists
    approved_by: <approver>        # Recommended: who approved it
    expires: <YYYY-MM-DD>          # Optional: date when this exemption stops applying
```

All filter fields (`namespace`, `resource`, `kind`, `checks`) are optional. An exemption matches a finding if all non-empty fields match. Empty fields are treated as wildcards.

### Examples

#### Exempt an entire namespace

```yaml
exemptions:
  - namespace: kube-system
    reason: "System namespace — elevated privileges expected"
    approved_by: "platform-team"
```

This skips all checks for all resources in `kube-system`.

#### Exempt specific checks for a namespace

```yaml
exemptions:
  - namespace: monitoring
    checks:
      - host-network
      - host-ports
    reason: "Prometheus needs host network for node metrics"
    approved_by: "sre-team"
```

This skips only the `host-network` and `host-ports` checks for resources in the `monitoring` namespace.

#### Exempt a specific resource

```yaml
exemptions:
  - namespace: default
    kind: Deployment
    resource: legacy-app
    checks:
      - run-as-root
    reason: "Legacy app requires root — tracked in JIRA-1234"
    approved_by: "security-team"
    expires: "2026-06-30"
```

This skips the `run-as-root` check only for the Deployment named `legacy-app` in the `default` namespace, and the exemption expires on June 30, 2026.

#### Temporary exemption with expiry

```yaml
exemptions:
  - namespace: staging
    checks:
      - resource-limits-missing
    reason: "Limits being rolled out incrementally — JIRA-5678"
    approved_by: "platform-team"
    expires: "2026-03-31"
```

After the expiry date, this exemption automatically stops applying and the findings will appear in scan results again.

## Annotation-Based Exemptions

Annotation-based exemptions are set directly on Kubernetes resources using the `kubevigil.io/skip` annotation. They are ideal for per-resource exceptions that travel with the manifest.

### Skip all checks

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: special-workload
  annotations:
    kubevigil.io/skip: "*"
spec:
  # ...
```

The wildcard `"*"` skips all KubeVigil checks for this resource.

### Skip specific checks

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: prometheus-node-exporter
  annotations:
    kubevigil.io/skip: "host-network,host-ports,privileged"
spec:
  # ...
```

Comma-separated check IDs skip only those specific checks. All other checks still run against this resource.

## When to Use Each Approach

| Approach | Best For |
|----------|----------|
| **Config-based** | Namespace-wide exemptions, team-level policies, temporary exemptions with expiry dates, centralized audit trail |
| **Annotation-based** | Per-resource exceptions, exceptions that should travel with the manifest in version control, quick one-off exemptions |

## Audit Trail

Both approaches support documenting the justification for each exemption:

- **Config-based**: Use the `reason` and `approved_by` fields. These fields are not enforced by KubeVigil but provide an audit trail for security reviews.
- **Annotation-based**: Add a companion annotation such as `kubevigil.io/skip-reason: "JIRA-1234 — approved by security team"` as a convention for your organization.

## Matching Logic

Configuration-based exemptions use the following matching logic:

1. If `namespace` is set, the finding's namespace must match exactly.
2. If `resource` is set, the finding's resource name must match exactly.
3. If `kind` is set, the finding's resource kind must match exactly.
4. If `checks` is set (non-empty list), the finding's check ID must be in the list.
5. If `expires` is set (YYYY-MM-DD format), the exemption stops applying after that date.
6. If all non-empty fields match, the finding is exempted.

Annotation-based exemptions are evaluated first. If a resource has a matching annotation, the finding is exempted regardless of configuration-based rules.

## Precedence

1. Annotation-based exemptions (`kubevigil.io/skip`) are checked first.
2. Configuration-based exemptions are checked second.
3. If either matches, the finding is suppressed.
