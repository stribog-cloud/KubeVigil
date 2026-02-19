# Performance and Severity Tuning

KubeVigil provides several tuning options to control scan performance, filter results by severity, customize exit behavior for CI pipelines, and disable or override individual checks.

## Concurrency

Control how many checks run in parallel using the `concurrency` setting or the `--concurrency` flag.

**Config file:**

```yaml
settings:
  concurrency: 20
```

**CLI flag:**

```bash
kubevigil scan --concurrency 20
```

The default is `10`. Increasing concurrency speeds up scans on large clusters at the cost of higher API server load. For very large clusters (hundreds of namespaces), consider values between 15 and 30. For constrained environments, reduce to 5 or lower.

## Severity Threshold

The `severity_threshold` setting controls the minimum severity level included in scan results. Findings below this threshold are filtered out entirely.

**Config file:**

```yaml
settings:
  severity_threshold: medium
```

**CLI flag:**

```bash
kubevigil scan --severity medium
```

Valid values: `info`, `low`, `medium`, `high`, `critical`

Default: `info` (all findings are included)

This is a display filter only. It does not affect which checks run, just which findings appear in the output.

## Fail-On Severity

The `fail_on` setting controls the minimum severity that triggers a non-zero exit code (exit 1). This is the primary mechanism for failing CI/CD pipelines on security findings.

**Config file:**

```yaml
settings:
  fail_on: high
```

**CLI flag:**

```bash
kubevigil scan --fail-on critical
```

Valid values: `info`, `low`, `medium`, `high`, `critical`

Default: `high`

Examples:

- `--fail-on critical` -- only critical findings cause failure (lenient)
- `--fail-on high` -- high and critical findings cause failure (default)
- `--fail-on medium` -- medium, high, and critical findings cause failure (strict)
- `--fail-on info` -- any finding causes failure (strictest)

## Timeout

The `timeout` setting controls the maximum duration for a scan. Uses Go duration format.

**Config file:**

```yaml
settings:
  timeout: 10m
```

Default: `5m`

For large clusters or slow API servers, increase the timeout. The scan will be cancelled and return an error if it exceeds the timeout.

## Disabling Checks

Disable specific checks by adding their IDs to the `checks.disabled` list. Use `kubevigil list checks` to see all available check IDs.

```yaml
checks:
  disabled:
    - image-tag-latest      # We use tag-based deployment strategy
    - runtime-class          # Not using custom runtimes
    - psp-still-present      # Already removed all PSPs
```

Disabled checks do not execute at all, saving scan time and eliminating unwanted noise.

## Severity Overrides

Override the default severity for any check to match your organization's risk tolerance.

```yaml
checks:
  overrides:
    host-path-volumes:
      severity: critical     # Treat as critical in our environment
    resource-limits-missing:
      severity: low          # Downgrade — we use LimitRanges instead
    image-tag-latest:
      severity: high         # Upgrade from medium
```

Overrides affect both the reported severity in output and the `--fail-on` threshold evaluation.

## Managed Resources Filtering

By default, KubeVigil filters out managed Pods and ReplicaSets to avoid duplicate findings. A Deployment creates a ReplicaSet, which creates Pods -- reporting findings on all three would be noisy. KubeVigil reports on the owner (Deployment) and filters out the managed resources.

To include managed resources:

**Config file:**

```yaml
settings:
  include_managed: true
```

**CLI flag:**

```bash
kubevigil scan --include-managed
```

## System Namespace Filtering

By default, KubeVigil excludes system namespaces (`kube-system`, `kube-public`, `kube-node-lease`) because system components legitimately require elevated privileges.

To include system namespaces:

```bash
kubevigil scan --include-system-namespaces
```

## Infrastructure Namespace Filtering

Infrastructure namespaces (monitoring, service mesh, storage) often have workloads that require elevated privileges by design. Use `--exclude-infra` to filter them out:

```bash
kubevigil scan --exclude-infra
```

Add custom namespaces to the infrastructure list:

```yaml
settings:
  exclude_infra: true
  infra_namespaces:
    - my-monitoring
    - my-service-mesh
```

## Finding Aggregation

By default, KubeVigil groups findings with the same check and message within a namespace. To see every finding individually:

```bash
kubevigil scan --no-aggregate
```

This is useful for counting exact occurrences or when piping output to other tools.

## Performance Tips for Large Clusters

1. **Increase concurrency**: Use `--concurrency 20` or higher for clusters with many namespaces.

2. **Filter by namespace**: Scan only relevant namespaces instead of the entire cluster.

   ```bash
   kubevigil scan -n production
   ```

3. **Exclude infrastructure**: Use `--exclude-infra` to skip infrastructure namespaces that have known elevated-privilege workloads.

4. **Disable irrelevant checks**: If certain checks are not applicable to your environment, disable them to reduce scan time.

   ```yaml
   checks:
     disabled:
       - cloud-provider-detection  # Not using cloud provider
       - eks-imds-access            # Not on EKS
       - gke-metadata-concealment   # Not on GKE
       - aks-pod-identity           # Not on AKS
   ```

5. **Use severity threshold**: If you only care about high and critical findings, set `--severity high` to reduce output volume.

6. **Increase timeout**: For very large clusters, increase the timeout to avoid premature cancellation.

   ```bash
   kubevigil scan --concurrency 30 --timeout 15m
   ```

7. **Use manifest mode for CI**: Scanning manifests from disk is faster than live cluster scanning because it avoids API server round trips.

   ```bash
   kubevigil scan -f manifests/
   ```
