# Troubleshooting

This page covers common issues, their causes, and solutions. For exit code meanings, see [Exit Codes](../reference/exit-codes.md).

## "cluster unreachable" or Connection Errors

**Symptom:** KubeVigil fails with a connection error when running a live cluster scan.

**Causes and solutions:**

1. **No kubeconfig configured.** KubeVigil uses the same kubeconfig as `kubectl`. Verify your config works:
   ```bash
   kubectl cluster-info
   ```

2. **Wrong context.** Specify the correct context explicitly:
   ```bash
   kubevigil scan --context my-cluster
   ```

3. **Custom kubeconfig path.** If your kubeconfig is not at `~/.kube/config`:
   ```bash
   kubevigil scan --kubeconfig /path/to/kubeconfig
   ```

4. **RBAC permissions.** KubeVigil needs read access to cluster resources. At minimum, the service account or user must have `get` and `list` permissions on workloads, namespaces, roles, and other scanned resource types. Test with:
   ```bash
   kubectl auth can-i list deployments --all-namespaces
   kubectl auth can-i list pods --all-namespaces
   kubectl auth can-i list clusterroles
   ```

5. **VPN or proxy.** If your cluster is behind a VPN or corporate proxy, ensure the connection is active before scanning.

## "no findings" When Findings Are Expected

**Symptom:** The scan completes but reports zero findings.

**Causes and solutions:**

1. **Severity threshold too high.** The `--severity` flag (or `settings.severity_threshold` in config) filters out findings below the threshold. Remove it to see all findings:
   ```bash
   kubevigil scan -f ./manifests/
   ```

2. **Checks disabled.** Your `.kubevigil.yaml` may have checks disabled:
   ```yaml
   checks:
     disabled:
       - privileged
       - run-as-root
   ```
   Remove entries from the `disabled` list or temporarily scan without a config:
   ```bash
   kubevigil scan -f ./manifests/ --config /dev/null
   ```

3. **Namespace filtering.** The `--namespace` flag limits results to one namespace. Resources in other namespaces are excluded. System namespaces (`kube-system`, `kube-public`, `kube-node-lease`) are excluded by default -- use `--include-system-namespaces` to include them.

4. **Exemptions.** Resources matching an exemption in `.kubevigil.yaml` are silently excluded. Check the `exemptions` section of your config file.

5. **Empty or unparseable files.** If manifest files contain only comments, non-Kubernetes YAML, or syntax errors, KubeVigil skips them silently. Use `--verbose` to see parse warnings:
   ```bash
   kubevigil scan -f ./manifests/ -v
   ```

## "permission denied" During Live Scan

**Symptom:** The scan runs but produces errors about forbidden resources.

**Solution:** KubeVigil needs read-only access to the Kubernetes API. Create a ClusterRole with the required permissions:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: kubevigil-reader
rules:
  - apiGroups: ["", "apps", "batch", "rbac.authorization.k8s.io", "networking.k8s.io", "policy", "storage.k8s.io"]
    resources: ["*"]
    verbs: ["get", "list"]
```

Bind it to your user or service account:

```bash
kubectl create clusterrolebinding kubevigil-reader \
  --clusterrole=kubevigil-reader \
  --user=your-user@example.com
```

KubeVigil never modifies cluster state -- it only reads.

## "config file error" or YAML Parse Failure

**Symptom:** KubeVigil exits with code 3 and a config error message.

**Causes and solutions:**

1. **YAML syntax error.** Validate your `.kubevigil.yaml`:
   ```bash
   python3 -c "import yaml; yaml.safe_load(open('.kubevigil.yaml'))"
   ```
   Common mistakes: tabs instead of spaces, missing colons, incorrect indentation.

2. **Unknown fields.** KubeVigil validates config structure. Check for typos in field names. Refer to the [Configuration File](../configuration/config-file.md) reference for valid fields.

3. **Invalid severity value.** Severity values must be one of: `info`, `low`, `medium`, `high`, `critical` (case-insensitive).

4. **Wrong config file.** KubeVigil auto-discovers `.kubevigil.yaml` in the current directory and parent directories. Use `--config` to point to the correct file:
   ```bash
   kubevigil scan -f ./manifests/ --config ./my-config.yaml
   ```

## "fix did nothing" or No Fixes Applied

**Symptom:** `kubevigil fix` reports no fixable findings or skips everything.

**Causes and solutions:**

1. **Risk level too low.** By default, only **Safe** fixes are included. Many checks require `--risk-level moderate` or `--risk-level aggressive`:
   ```bash
   kubevigil fix ./manifests/ --risk-level moderate
   ```
   The dry-run output shows a breakdown of skipped fixes by risk classification.

2. **No auto-fixable findings.** Not all checks have auto-fix strategies. Currently 20 checks are auto-fixable. Run a scan to see which findings have fix hints:
   ```bash
   kubevigil scan -f ./manifests/ -o json | grep fix_hint
   ```

3. **System namespace protection.** Resources in system namespaces (`kube-system`, `kube-public`, `kube-node-lease`) are never auto-fixed unless you explicitly opt in:
   ```bash
   kubevigil fix ./manifests/ --apply --i-understand-system-namespaces
   ```

4. **Findings filtered out.** The `--checks`, `--severity`, `--namespace`, and `--fingerprint` flags on the fix command narrow which findings are eligible. Remove filters to include everything:
   ```bash
   kubevigil fix ./manifests/
   ```

5. **Forgot `--apply`.** Without `--apply`, the fix command runs in dry-run mode and modifies nothing. This is by design. Add `--apply` to write changes to disk:
   ```bash
   kubevigil fix ./manifests/ --apply
   ```

## Large Cluster Timeouts

**Symptom:** Scanning a large cluster times out or takes excessively long.

**Solutions:**

1. **Increase concurrency.** By default, KubeVigil runs checks with limited parallelism. Increase it:
   ```bash
   kubevigil scan --concurrency 20
   ```
   Or set it in `.kubevigil.yaml`:
   ```yaml
   settings:
     concurrency: 20
   ```

2. **Increase timeout.** The default timeout may not be enough for large clusters. Set a longer timeout in your config:
   ```yaml
   settings:
     timeout: "10m"
   ```

3. **Narrow the scope.** Scan a single namespace instead of the entire cluster:
   ```bash
   kubevigil scan -n production
   ```
   Or exclude infrastructure namespaces:
   ```bash
   kubevigil scan --exclude-infra
   ```

4. **Use manifest mode.** If you have the manifests on disk, scanning files is faster than querying the API:
   ```bash
   kubevigil scan -f ./manifests/
   ```

## Verbose Output for Debugging

Enable verbose logging to see detailed information about what KubeVigil is doing:

```bash
kubevigil scan -f ./manifests/ -v
```

Verbose output (`-v` or `--verbose`) logs to stderr and includes:

- Configuration loading details
- Which checks are enabled/disabled
- Manifest parse warnings
- Per-check timing information
- Resource discovery details (live mode)

## Exit Code Reference

KubeVigil uses specific exit codes to communicate scan and fix results:

### Scan Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan successful, no findings above `--fail-on` threshold |
| `1` | Findings found at or above `--fail-on` severity |
| `2` | Runtime error |
| `3` | Configuration error |

### Fix Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Fix successful -- all planned fixes applied (or dry-run shows changes) |
| `1` | Fix applied but `--verify` found remaining findings |
| `2` | Fix error -- total failure |
| `3` | Configuration error |
| `4` | No fixable findings found |
| `5` | Partial success -- some fixes applied but some files failed |

For the full reference, see [Exit Codes](../reference/exit-codes.md).

## Reporting Bugs

If you encounter an issue not covered here:

1. Reproduce the issue with verbose output:
   ```bash
   kubevigil scan -f ./manifests/ -v 2> debug.log
   ```
2. Check the [KubeVigil version](../reference/cli-reference.md):
   ```bash
   kubevigil version
   ```
3. Open a GitHub issue at [github.com/stribog-cloud/kubevigil/issues](https://github.com/stribog-cloud/kubevigil/issues) with:
   - KubeVigil version (`kubevigil version` output)
   - Command that triggered the issue
   - Relevant verbose log output (redact sensitive information)
   - Expected vs. actual behavior

## See Also

- [Exit Codes](../reference/exit-codes.md) -- complete exit code reference
- [Configuration File](../configuration/config-file.md) -- `.kubevigil.yaml` reference
- [CLI Reference](../reference/cli-reference.md) -- all commands and flags
