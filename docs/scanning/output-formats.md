# Output Formats

KubeVigil supports 8 output formats for scan results. The format is selected with the `-o` flag, which accepts either a format name (output to stdout) or a file path (format inferred from the extension).

```bash
# Format name -- writes to stdout
kubevigil scan -o json

# File path -- format inferred from extension, writes to file
kubevigil scan -o report.html
```

## File Extension Mapping

When `-o` is a file path, the format is inferred from the extension:

| Extension | Format |
|-----------|--------|
| `.html`, `.htm` | HTML |
| `.json` | JSON |
| `.md` | Markdown |
| `.yaml`, `.yml` | YAML |
| `.sarif` | SARIF |
| `.xml` | JUnit XML |
| `.csv` | CSV |
| `.txt` | Text |

## Text (Default)

Colored terminal output grouped by check, with a summary table. This is the default when no `-o` flag is provided.

```bash
kubevigil scan
kubevigil scan -o text
```

### Text Options

| Flag | Description |
|------|-------------|
| `--summary-only` | Show only the summary table, omitting individual findings |
| `--no-aggregate` | Show every finding individually instead of grouping by check |
| `--no-color` | Disable ANSI color codes |

```bash
# Summary table only
kubevigil scan --summary-only

# Flat list of all findings
kubevigil scan --no-aggregate

# CI-friendly: no color codes
kubevigil scan --no-color
```

## JSON

Full structured output containing all scan metadata, findings, cluster info, and summary statistics.

```bash
kubevigil scan -o json
kubevigil scan -o results.json
```

### JSON Structure

```json
{
  "version": "1",
  "tool_version": "0.1.0",
  "scan_result": {
    "summary": {
      "total_checks": 150,
      "total_findings": 42,
      "by_severity": {
        "critical": 2,
        "high": 8,
        "medium": 20,
        "low": 10,
        "info": 2
      },
      "posture_score": 68
    },
    "findings": [
      {
        "checker": "privileged",
        "severity": "critical",
        "resource": "my-deployment",
        "namespace": "default",
        "kind": "Deployment",
        "message": "Container 'app' runs in privileged mode",
        "remediation": "Set securityContext.privileged to false"
      }
    ],
    "cluster_info": {
      "context_name": "my-cluster",
      "server_version": "1.28.0"
    },
    "scan_meta": {
      "mode": "live",
      "duration_ms": 1234,
      "timestamp": "2025-01-15T10:30:00Z"
    }
  }
}
```

### jq Examples

```bash
# Count total findings
kubevigil scan -o json | jq '.scan_result.summary.total_findings'

# List all critical findings
kubevigil scan -o json | jq '.scan_result.findings[] | select(.severity == "critical")'

# Extract the posture score
kubevigil scan -o json | jq '.scan_result.summary.posture_score'

# Group findings by namespace
kubevigil scan -o json | jq '.scan_result.findings | group_by(.namespace) | map({namespace: .[0].namespace, count: length})'

# List unique check IDs with finding counts
kubevigil scan -o json | jq '.scan_result.findings | group_by(.checker) | map({check: .[0].checker, count: length}) | sort_by(-.count)'
```

## Markdown

Generates a Markdown report suitable for pull requests, wikis, and documentation. Includes summary tables, findings grouped by severity, and remediation guidance.

```bash
kubevigil scan -o markdown
kubevigil scan -o report.md
```

## YAML

Outputs the same structured data as JSON but in YAML format, useful for integration with Kubernetes-native tooling and workflows.

```bash
kubevigil scan -o yaml
kubevigil scan -o results.yaml
```

## HTML

Generates a self-contained HTML report with inline CSS and JavaScript. No external dependencies -- the file can be opened directly in any browser.

```bash
kubevigil scan -o report.html
```

### Features

- **Dark mode**: Automatic detection via `prefers-color-scheme`, with a manual toggle
- **Interactive filtering**: Filter findings by severity, namespace, check, and framework
- **Posture score gauge**: Visual gauge showing overall security posture (A through F grading)
- **Compliance mapping**: Findings mapped to CIS, MITRE ATT&CK, and NSA/CISA frameworks
- **CSV/JSON export**: Built-in buttons to export filtered findings as CSV or JSON
- **Remediation drawer**: Click any finding to see detailed remediation guidance in a side panel

## SARIF 2.1.0

Static Analysis Results Interchange Format, the industry standard for static analysis tools. Compatible with GitHub Code Scanning, VS Code SARIF Viewer, and Azure DevOps.

```bash
kubevigil scan -o results.sarif
```

### GitHub Code Scanning Integration

Upload the SARIF file to GitHub's code scanning API to see findings directly in the Security tab and as PR annotations:

```bash
kubevigil scan -f ./manifests/ -o results.sarif
# Upload via GitHub Actions (see CI Integration for the full workflow)
```

### VS Code Integration

Install the "SARIF Viewer" extension, then open the `.sarif` file to see findings inline in your editor with full navigation.

## JUnit XML

Generates a JUnit-compatible XML report where each finding is a test failure. Compatible with Jenkins, GitLab CI, CircleCI, and any CI system that consumes JUnit XML.

```bash
kubevigil scan -o results.xml
```

Each check becomes a test case in the report. Checks with findings are marked as failures with the finding details in the failure message.

### CI Integration Examples

**Jenkins**: Archive the XML as a test result:
```groovy
junit 'results.xml'
```

**GitLab CI**: Add as a JUnit artifact:
```yaml
artifacts:
  reports:
    junit: results.xml
```

## CSV

Generates a comma-separated values file with one row per finding. Suitable for import into spreadsheets, databases, or data analysis tools.

```bash
kubevigil scan -o findings.csv
```

The CSV includes columns for check ID, severity, resource, namespace, kind, message, and remediation.
