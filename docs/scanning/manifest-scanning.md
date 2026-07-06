# Manifest Scanning

KubeVigil can scan Kubernetes YAML manifests without connecting to a cluster. This mode parses YAML files directly, making it ideal for CI/CD pipelines, pre-commit hooks, and code reviews.

## How It Works

Manifest scanning reads YAML files from disk, parses each Kubernetes resource definition, and runs all applicable security checks against them. No cluster connection or kubeconfig is required.

134 of KubeVigil's 150 checks work in manifest mode. The remaining 15 are live-only checks that require cluster runtime state (see [Live Cluster Scanning](live-cluster.md) for details). One check -- `secrets-hardcoded-manifests` -- runs exclusively in manifest mode, detecting hardcoded secrets in YAML files.

## Scanning a Single File

```bash
kubevigil scan -f deployment.yaml
```

## Scanning a Directory

Pass a directory path to recursively scan all `.yaml` and `.yml` files within it:

```bash
kubevigil scan -f ./manifests/
```

KubeVigil walks the directory tree and processes every YAML file it finds. Non-YAML files are silently skipped.

## Multi-Document YAML

KubeVigil fully supports multi-document YAML files that use `---` separators. Each document in the file is parsed and checked independently:

```yaml
# multi-resource.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: frontend
spec:
  # ...
---
apiVersion: v1
kind: Service
metadata:
  name: frontend-svc
spec:
  # ...
```

```bash
kubevigil scan -f multi-resource.yaml
```

Both the Deployment and the Service are scanned and reported individually.

## Use Cases

### CI/CD Pipelines

Manifest scanning is the primary integration point for CI/CD. It requires no cluster access, runs quickly, and produces structured output suitable for automated processing.

```bash
# Fail the pipeline if any high+ severity findings exist
kubevigil scan -f ./k8s/ --fail-on high
```

See [CI Integration](ci-integration.md) for full pipeline examples.

### Pre-Commit Hooks

Catch security issues before they reach version control:

```bash
# In a pre-commit hook script
kubevigil scan -f ./manifests/ --fail-on medium --no-color
```

### Pull Request Reviews

Generate a SARIF report for GitHub Security tab integration, or a Markdown report for inline PR comments:

```bash
# SARIF for GitHub code scanning
kubevigil scan -f ./manifests/ -o results.sarif

# Markdown for PR comments
kubevigil scan -f ./manifests/ -o markdown
```

## Combining with Output Formats

Manifest scanning works with all 8 output formats. The output format is specified with `-o`:

```bash
# JSON to stdout
kubevigil scan -f ./manifests/ -o json

# SARIF to file (format inferred from .sarif extension)
kubevigil scan -f ./manifests/ -o results.sarif

# HTML report to file
kubevigil scan -f ./manifests/ -o security-report.html

# JUnit XML for CI test reporting
kubevigil scan -f ./manifests/ -o results.xml

# CSV for spreadsheet analysis
kubevigil scan -f ./manifests/ -o findings.csv
```

See [Output Formats](output-formats.md) for details on each format.

## Exit Codes for CI

KubeVigil uses exit codes to communicate results to CI systems:

| Code | Meaning |
|------|---------|
| `0` | Scan completed, no findings above the `--fail-on` threshold |
| `1` | Findings detected above the `--fail-on` threshold |
| `2` | Scan error (file not found, parse error, etc.) |
| `3` | Configuration error (invalid flags, malformed config file) |

### Using Exit Codes in Scripts

```bash
kubevigil scan -f ./manifests/ --fail-on high
status=$?

if [ $status -eq 0 ]; then
  echo "No high+ findings -- safe to deploy"
elif [ $status -eq 1 ]; then
  echo "Security findings detected -- blocking deploy"
  exit 1
elif [ $status -eq 2 ]; then
  echo "Scan error -- investigate"
  exit 2
fi
```

## Text Output Options

When using the default text output, two flags control verbosity:

```bash
# Show only the summary table, no individual findings
kubevigil scan -f ./manifests/ --summary-only

# Show every finding individually instead of grouping by check
kubevigil scan -f ./manifests/ --no-aggregate
```

## Disabling Color

For CI environments or piped output, disable ANSI color codes:

```bash
kubevigil scan -f ./manifests/ --no-color
```

## Configuration

Manifest scanning respects the same `.kubevigil.yaml` configuration file as live scanning. Place it in your repository root and KubeVigil will auto-discover it:

```yaml
# .kubevigil.yaml
settings:
  fail_on: high
  severity_threshold: medium

exemptions:
  - check: resource-limits-missing
    resource: debug-pod
    reason: "Debug pod, no limits needed"
```
