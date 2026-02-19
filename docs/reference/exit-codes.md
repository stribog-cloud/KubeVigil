# Exit Codes

KubeVigil uses distinct exit codes for the `scan` and `fix` commands to communicate results to CI/CD pipelines and shell scripts. Exit codes enable automated decision-making without parsing output.

## Scan Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Clean -- no findings at or above the `--fail-on` threshold |
| `1` | Findings exist at or above the `--fail-on` severity |
| `2` | Scan error (invalid path, cluster unreachable, API error) |
| `3` | Configuration error (invalid config file, bad flag values) |

## Fix Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Fix successful -- all planned fixes applied (or dry-run shows changes) |
| `1` | Fixes applied but `--verify` found remaining findings |
| `2` | Total failure (backup failed, no files could be processed) |
| `3` | Configuration error (invalid flags, conflicting options) |
| `4` | Nothing to fix -- no fixable findings found at the current risk level |
| `5` | Partial success -- some fixes applied but some files failed |

## CI/CD Usage Examples

### GitHub Actions -- Scan

```yaml
- name: Security Scan
  run: kubevigil scan -f manifests/ --fail-on high -o results.sarif
  continue-on-error: true
  id: scan

- name: Upload SARIF
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif

- name: Check scan result
  if: steps.scan.outcome == 'failure'
  run: |
    echo "Security findings above threshold detected"
    exit 1
```

### GitHub Actions -- Fix

```yaml
- name: Auto-fix safe issues
  run: |
    kubevigil fix manifests/ --apply --yes --risk-level safe
    FIX_EXIT=$?
    if [ $FIX_EXIT -eq 0 ]; then
      echo "All fixes applied successfully"
    elif [ $FIX_EXIT -eq 4 ]; then
      echo "No fixable findings — nothing to do"
    elif [ $FIX_EXIT -eq 5 ]; then
      echo "Partial success — some files could not be fixed"
      exit 1
    else
      echo "Fix failed with exit code $FIX_EXIT"
      exit 1
    fi
```

### Shell Script -- Scan with Threshold Control

```bash
#!/bin/bash
kubevigil scan --fail-on medium -o json > results.json
EXIT_CODE=$?

case $EXIT_CODE in
  0) echo "No findings above medium severity" ;;
  1) echo "Findings detected — review results.json"
     exit 1 ;;
  2) echo "Scan error — check cluster connectivity"
     exit 2 ;;
  3) echo "Configuration error — check .kubevigil.yaml"
     exit 3 ;;
esac
```

### Shell Script -- Fix with Verification

```bash
#!/bin/bash
kubevigil fix manifests/ --apply --yes --verify --risk-level moderate
EXIT_CODE=$?

case $EXIT_CODE in
  0) echo "All fixes applied and verified" ;;
  1) echo "Fixes applied but some findings remain"
     exit 1 ;;
  2) echo "Fix failed completely"
     exit 2 ;;
  3) echo "Configuration error"
     exit 3 ;;
  4) echo "Nothing to fix"
     exit 0 ;;
  5) echo "Partial success — check fix report"
     exit 1 ;;
esac
```

### GitLab CI -- Scan as Quality Gate

```yaml
security-scan:
  stage: test
  script:
    - kubevigil scan -f manifests/ --fail-on high -o junit > kubevigil-report.xml
  artifacts:
    reports:
      junit: kubevigil-report.xml
    when: always
  allow_failure: false
```

## Combining Exit Codes with Output Formats

For CI/CD pipelines, combine exit codes with machine-readable output formats for both automated decisions and human review:

```bash
# JSON for machine parsing, exit code for pipeline control
kubevigil scan -f manifests/ --fail-on high -o results.json

# SARIF for GitHub Advanced Security integration
kubevigil scan -f manifests/ --fail-on high -o findings.sarif

# JUnit for test reporting in CI dashboards
kubevigil scan -f manifests/ --fail-on high -o kubevigil.junit
```
