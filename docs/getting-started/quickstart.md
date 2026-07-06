# Quickstart

This page gets you from zero to scan results in under a minute. For deeper coverage, see the [scanning docs](../scanning/output-formats.md) and [configuration docs](../configuration/).

## Scan a Manifest File

No cluster required. Point KubeVigil at any Kubernetes YAML file:

```bash
kubevigil scan -f deployment.yaml
```

Scan an entire directory of manifests:

```bash
kubevigil scan -f ./manifests/
```

KubeVigil parses Deployments, StatefulSets, DaemonSets, Jobs, CronJobs, Pods, Services, Roles, ClusterRoles, and more. Multi-document YAML files work out of the box.

## Scan a Live Cluster

With a valid kubeconfig, scan your current cluster context:

```bash
kubevigil scan
```

Use a specific context or namespace:

```bash
kubevigil scan --context staging --namespace app-team
```

KubeVigil reads from the Kubernetes API. It never modifies cluster state.

## Filter by Severity

Show only high and critical findings:

```bash
kubevigil scan -f ./manifests/ --severity high
```

Valid severity levels: `critical`, `high`, `medium`, `low`, `info`. The flag sets a minimum threshold -- `--severity high` includes both High and Critical.

## Choose an Output Format

KubeVigil supports 8 output formats. Use `-o` to select one:

```bash
# JSON (for programmatic consumption)
kubevigil scan -f ./manifests/ -o json

# HTML report (open in a browser)
kubevigil scan -f ./manifests/ -o report.html

# SARIF (GitHub Security tab integration)
kubevigil scan -f ./manifests/ -o results.sarif

# Markdown (paste into a PR comment)
kubevigil scan -f ./manifests/ -o markdown

# YAML, JUnit XML, CSV
kubevigil scan -f ./manifests/ -o yaml
kubevigil scan -f ./manifests/ -o junit
kubevigil scan -f ./manifests/ -o csv
```

When the `-o` value contains a file extension (e.g., `report.html`, `results.sarif`), KubeVigil writes to that file and infers the format from the extension. Otherwise, output goes to stdout.

## Filter by Compliance Framework

Show only findings mapped to a specific framework:

```bash
kubevigil scan -f ./manifests/ --framework cis
kubevigil scan -f ./manifests/ --framework mitre
kubevigil scan -f ./manifests/ --framework nsa
```

## Preview Auto-Fixes

See what KubeVigil would change without modifying any files:

```bash
kubevigil fix ./manifests/
```

This runs a scan, identifies fixable findings, and prints a colored diff. No files are touched.

## Apply Safe Fixes

Apply zero-risk fixes (e.g., setting `privileged: false`, disabling service account token auto-mount):

```bash
kubevigil fix ./manifests/ --apply
```

Every `--apply` creates a backup directory with a `RESTORE.md` file. To include fixes with very low risk (like `drop: ["ALL"]` for capabilities):

```bash
kubevigil fix ./manifests/ --apply --risk-level moderate
```

To verify that fixes resolved the findings, add `--verify`:

```bash
kubevigil fix ./manifests/ --apply --verify
```

## List Available Checks

See all 150 security checks with their IDs, categories, and supported scan modes:

```bash
kubevigil list checks
```

## Set a Failure Threshold for CI

Exit with code 1 when findings meet or exceed a severity. Useful in CI pipelines:

```bash
kubevigil scan -f ./manifests/ --fail-on high
```

## Next Steps

- [Key Concepts](concepts.md) -- understand the data model behind checks, findings, and scores
- [Output Formats](../scanning/output-formats.md) -- details on all 8 formats
- [Configuration](../configuration/) -- exemptions, severity overrides, and `.kubevigil.yaml`
- [Checks Overview](../checks/) -- browse all 150 checks by category
