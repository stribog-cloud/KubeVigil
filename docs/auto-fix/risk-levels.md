# Risk Levels

Every auto-fixable check in KubeVigil is classified into a safety tier that reflects the risk of the fix breaking application functionality. Risk levels control which fixes are applied with `--apply`.

## How Risk Levels Work

Risk levels are **additive**. Each level includes all fixes from lower levels:

| `--risk-level` | What Gets Applied |
|-----------------|-------------------|
| `safe` (default) | Safe only |
| `moderate` | Safe + Likely Safe |
| `aggressive` | Safe + Likely Safe + Potentially Breaking |

**Manual Only** fixes are never auto-applied at any risk level. They appear in the fix report with guidance.

```bash
# Apply only safe fixes (default)
kubevigil fix ./manifests/ --apply

# Apply safe + likely safe
kubevigil fix ./manifests/ --apply --risk-level moderate

# Apply all auto-fixable checks
kubevigil fix ./manifests/ --apply --risk-level aggressive
```

## Safe (Zero Risk)

These fixes disable clearly dangerous settings that standard workloads should never use. Applying them has no impact on correctly written applications.

| Check ID | Fix | Impact |
|----------|-----|--------|
| `privileged` | Sets `securityContext.privileged: false` | None -- containers should never run privileged unless they are known system components |
| `privilege-escalation` | Sets `securityContext.allowPrivilegeEscalation: false` | None for standard workloads |
| `host-pid` | Sets `spec.hostPID: false` | None unless container specifically needs host PID visibility |
| `host-ipc` | Sets `spec.hostIPC: false` | None unless container uses shared memory with host |
| `proc-mount` | Sets `securityContext.procMount: Default` | None -- Default is the standard setting |
| `share-process-namespace` | Sets `spec.shareProcessNamespace: false` | None unless containers need to share process visibility |
| `automount-token` | Sets `spec.automountServiceAccountToken: false` | Pods that need Kubernetes API access will fail without a token |

**7 checks** at this level.

```bash
# Preview safe fixes
kubevigil fix ./manifests/

# Apply safe fixes
kubevigil fix ./manifests/ --apply
```

## Likely Safe (Very Low Risk)

These fixes apply security best practices that the vast majority of workloads support. In rare cases, specific applications may need adjustment after these fixes.

| Check ID | Fix | Impact |
|----------|-----|--------|
| `capabilities-added` | Removes dangerous added capabilities | Containers requiring specific capabilities will fail |
| `capabilities-not-dropped` | Sets `capabilities.drop: ["ALL"]` | Containers needing specific capabilities must explicitly add them back |
| `run-as-root` | Sets `securityContext.runAsNonRoot: true` | Containers that require root will fail to start |
| `read-only-rootfs` | Sets `securityContext.readOnlyRootFilesystem: true` | Apps writing to the container filesystem need emptyDir volumes |
| `host-network` | Sets `spec.hostNetwork: false` | Containers binding to host ports will lose network access |
| `seccomp-profile` | Adds `seccompProfile.type: RuntimeDefault` | Containers using uncommon syscalls may crash |
| `image-pull-policy` | Sets `imagePullPolicy: Always` | Slightly slower pod starts due to image verification |
| `psa-labels-missing` | Adds `pod-security.kubernetes.io/enforce: baseline` label | New pods violating baseline will be rejected |
| `psa-mode-audit-only` | Changes PSA mode from `audit` to `enforce` | Pods violating PSA policy will be rejected |

**9 checks** at this level.

```bash
# Preview safe + likely safe
kubevigil fix ./manifests/ --risk-level moderate

# Apply safe + likely safe
kubevigil fix ./manifests/ --apply --risk-level moderate
```

## Potentially Breaking (May Break Functionality)

These fixes apply conservative defaults that could affect application behavior. Review the diff carefully before applying.

| Check ID | Fix | Impact |
|----------|-----|--------|
| `resource-limits-missing` | Adds default limits: `cpu: 500m`, `memory: 256Mi` | Applications exceeding limits will be throttled or OOMKilled |
| `resource-requests-missing` | Adds default requests: `cpu: 100m`, `memory: 128Mi` | May affect scheduling if cluster resources are constrained |
| `ephemeral-storage-limits` | Adds default ephemeral-storage limit: `1Gi` | Containers exceeding limit will be evicted |
| `host-ports` | Removes `hostPort` from container ports | External traffic routing via host ports will stop working |

**4 checks** at this level.

```bash
# Preview all fixes including potentially breaking
kubevigil fix ./manifests/ --risk-level aggressive

# Apply all fixes
kubevigil fix ./manifests/ --apply --risk-level aggressive
```

When potentially breaking fixes are included in the diff output, impact warnings are printed inline:

```
# IMPACT (potentially_breaking): Applications exceeding limits will be throttled or OOMKilled.
```

## Manual Only (Guidance Only)

Some checks cannot be auto-fixed because the correct remediation depends on application-specific context. These never appear in the fix plan but are documented in the fix report when `--report` is used.

Examples of manual-only findings:

- **RBAC restructuring**: Overly permissive ClusterRoles require understanding of what each service actually needs
- **NetworkPolicy creation**: Correct policies depend on application communication patterns
- **Complex security context changes**: Some workloads have legitimate reasons for specific settings

## Filtering by Check or Severity

Target specific checks or severities instead of relying on risk level alone:

```bash
# Fix only specific checks
kubevigil fix ./manifests/ --apply --checks privileged,privilege-escalation

# Fix only high severity findings
kubevigil fix ./manifests/ --apply --severity high,critical

# Fix only a specific namespace
kubevigil fix ./manifests/ --apply -n production

# Fix a specific finding by fingerprint
kubevigil fix ./manifests/ --apply --fingerprint a1b2c3d4e5f6
```

## Viewing the Summary

The dry-run summary shows how many fixes fall into each risk tier and what would happen at the current risk level:

```
By risk classification:
  Safe:                  5  [will be applied]
  Likely safe:           3  [skipped -- use --risk-level moderate]
  Potentially breaking:  1  [skipped -- use --risk-level aggressive]
```

This helps you make an informed decision about which risk level to use before committing to `--apply`.
