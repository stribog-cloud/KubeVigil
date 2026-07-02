# CI Integration

KubeVigil is designed for CI/CD pipelines. Manifest scanning requires no cluster access, produces structured output, and uses exit codes that CI systems understand.

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No findings above the `--fail-on` threshold |
| `1` | Findings detected above the threshold |
| `2` | Scan error |
| `3` | Configuration error |

## GitHub Actions

### Scan Manifests and Upload SARIF

This workflow scans Kubernetes manifests on every push and pull request, then uploads results to the GitHub Security tab:

```yaml
name: KubeVigil Security Scan
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write  # Required for SARIF upload
    steps:
      - uses: actions/checkout@v4

      - name: Install KubeVigil
        run: |
          curl -sSL https://raw.githubusercontent.com/stribog-cloud/KubeVigil/main/install.sh | bash

      - name: Run security scan
        run: kubevigil scan -f ./manifests/ -o results.sarif --no-color
        continue-on-error: true

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif

      - name: Fail on high severity findings
        run: kubevigil scan -f ./manifests/ --fail-on high --no-color
```

### Scan with Multiple Reports

Generate both SARIF for the Security tab and HTML for human review:

```yaml
      - name: Run security scan (SARIF)
        run: kubevigil scan -f ./manifests/ -o results.sarif --no-color
        continue-on-error: true

      - name: Run security scan (HTML)
        run: kubevigil scan -f ./manifests/ -o security-report.html --no-color
        continue-on-error: true

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif

      - name: Upload HTML report
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: security-report.html

      - name: Gate on findings
        run: kubevigil scan -f ./manifests/ --fail-on high --no-color
```

## GitLab CI

### Scan with JUnit Report

GitLab CI natively consumes JUnit XML for test reporting. This configuration shows findings in the merge request test report:

```yaml
security-scan:
  stage: test
  image: golang:1.22
  before_script:
    - curl -sSL https://raw.githubusercontent.com/stribog-cloud/KubeVigil/main/install.sh | bash
  script:
    - kubevigil scan -f ./manifests/ -o results.xml --no-color
    - kubevigil scan -f ./manifests/ --fail-on high --no-color
  artifacts:
    when: always
    reports:
      junit: results.xml
```

### Scan with SARIF and Markdown

```yaml
security-scan:
  stage: test
  script:
    - kubevigil scan -f ./manifests/ -o results.sarif --no-color
    - kubevigil scan -f ./manifests/ -o report.md --no-color
    - kubevigil scan -f ./manifests/ --fail-on high --no-color
  artifacts:
    when: always
    paths:
      - results.sarif
      - report.md
```

## Generic CI

For any CI system, the key integration points are:

1. **Exit codes**: KubeVigil exits with `1` when findings exceed the `--fail-on` threshold, causing the CI step to fail.
2. **Structured output**: Use `-o json`, `-o sarif`, or `-o results.xml` for machine-readable results.
3. **No color**: Always pass `--no-color` in CI environments to avoid ANSI escape codes in logs.

```bash
# Basic CI gate -- fail on high severity
kubevigil scan -f ./manifests/ --fail-on high --no-color

# Generate a report and gate separately
kubevigil scan -f ./manifests/ -o results.json --no-color
kubevigil scan -f ./manifests/ --fail-on high --no-color
```

KubeVigil automatically detects CI environments (`CI=true`, `GITHUB_ACTIONS=true`, `GITLAB_CI=true`, `JENKINS_URL` set) and adjusts behavior accordingly, such as disabling interactive prompts for the `fix` command.

## Pre-Commit Hook

Add KubeVigil as a pre-commit hook to catch issues before code is committed. Create or edit `.git/hooks/pre-commit`:

```bash
#!/bin/bash
set -e

# Find all staged YAML files in the manifests directory
STAGED_YAML=$(git diff --cached --name-only --diff-filter=ACM -- '*.yaml' '*.yml' | grep -E '^manifests/' || true)

if [ -z "$STAGED_YAML" ]; then
  exit 0
fi

echo "Running KubeVigil security scan on staged manifests..."

# Create a temporary directory with staged file contents
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

for file in $STAGED_YAML; do
  mkdir -p "$TMPDIR/$(dirname $file)"
  git show ":$file" > "$TMPDIR/$file"
done

kubevigil scan -f "$TMPDIR/manifests/" --fail-on high --no-color

echo "Security scan passed."
```

Make it executable:

```bash
chmod +x .git/hooks/pre-commit
```

### Using pre-commit framework

If you use the [pre-commit](https://pre-commit.com/) framework, add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: kubevigil
        name: KubeVigil Security Scan
        entry: kubevigil scan -f
        language: system
        files: '\.ya?ml$'
        pass_filenames: true
        args: ['--fail-on', 'high', '--no-color']
```

## PR Decoration with SARIF

When SARIF results are uploaded via `github/codeql-action/upload-sarif`, GitHub automatically:

1. Shows findings in the **Security** tab under **Code scanning alerts**
2. Annotates pull request diffs with inline findings
3. Tracks finding status across commits (new, fixed, existing)

This gives reviewers immediate visibility into security issues directly in the PR review interface without needing to read log output.

## Configuration for CI

Place a `.kubevigil.yaml` in your repository root to set consistent defaults across all CI runs:

```yaml
# .kubevigil.yaml
settings:
  fail_on: high
  severity_threshold: medium
  concurrency: 5

version: "1"

exemptions:
  - checks: [resource-limits-missing]
    resource: debug-tools
    namespace: dev
    reason: "Debug tooling, limits not applicable"

  - checks: [image-tag-latest]
    resource: dev-runner
    reason: "Dev image, always pulls latest"
```

This ensures every developer and CI run uses the same exemptions and thresholds. CLI flags override config file values when both are specified.
