# SARIF Integration

KubeVigil produces [SARIF v2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) (Static Analysis Results Interchange Format) output, the industry standard for static analysis tools. SARIF is consumed by GitHub Code Scanning, VS Code, Azure DevOps, and dozens of other platforms.

## Generate SARIF Output

Write SARIF to a file by specifying a `.sarif` extension:

```bash
kubevigil scan -f ./manifests/ -o results.sarif
```

Or pipe to stdout with the format name:

```bash
kubevigil scan -f ./manifests/ -o sarif > results.sarif
```

Both produce identical output. The file-extension form is convenient when you want KubeVigil to create the file directly.

## SARIF Output Structure

KubeVigil emits a single SARIF run with three sections:

| Section | Contents |
|---------|----------|
| `tool.driver` | Tool name (`kubevigil`), version, information URI, and rules array |
| `tool.driver.rules` | One rule per unique check ID (e.g., `privileged`, `run-as-root`). Includes default severity level and compliance framework tags. |
| `results` | One result per finding. Each result references a rule, includes the finding message, severity level, and a logical location (resource name, namespace, field path). |

Severity mapping from KubeVigil to SARIF levels:

| KubeVigil Severity | SARIF Level |
|--------------------|-------------|
| **Critical**, **High** | `error` |
| **Medium** | `warning` |
| **Low**, **Info** | `note` |

The `properties` block on each run includes aggregate metrics: posture score, severity counts, unique resources, unique namespaces, and check coverage statistics.

## GitHub Code Scanning

Upload SARIF results to the GitHub Security tab using the CodeQL upload action. Findings appear as code scanning alerts on your repository.

### GitHub Actions Workflow

```yaml
name: KubeVigil Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  security-events: write

jobs:
  kubevigil:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install KubeVigil
        run: |
          go install github.com/stribog-cloud/kubevigil/cmd/kubevigil@latest

      - name: Run KubeVigil
        run: kubevigil scan -f ./k8s/ -o results.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
        if: always()
```

Key points:

- The `security-events: write` permission is required for SARIF upload.
- Use `if: always()` on the upload step so results are uploaded even when the scan exits non-zero (i.e., findings exceed `--fail-on` threshold).
- After upload, findings appear under **Security > Code scanning alerts** on your repository.

### Combining with Failure Thresholds

To fail the CI job on high-severity findings while still uploading all results:

```yaml
      - name: Run KubeVigil
        run: kubevigil scan -f ./k8s/ -o results.sarif --fail-on high
        continue-on-error: true
        id: scan

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
        if: always()

      - name: Check scan result
        if: steps.scan.outcome == 'failure'
        run: exit 1
```

## VS Code

The [SARIF Viewer](https://marketplace.visualstudio.com/items?itemName=MS-SarifVSCode.sarif-viewer) extension displays SARIF results as inline annotations in VS Code.

1. Install the **SARIF Viewer** extension from the marketplace.
2. Generate a SARIF file:
   ```bash
   kubevigil scan -f ./manifests/ -o results.sarif
   ```
3. Open `results.sarif` in VS Code. The extension parses the file and highlights findings inline in referenced files.

For a live workflow, see [IDE Integration](ide.md).

## Azure DevOps

Azure DevOps Advanced Security supports SARIF uploads. Add a step to your pipeline:

```yaml
steps:
  - script: kubevigil scan -f ./k8s/ -o results.sarif
    displayName: Run KubeVigil

  - task: PublishBuildArtifacts@1
    inputs:
      pathToPublish: results.sarif
      artifactName: CodeAnalysisLogs
    displayName: Upload SARIF
```

Azure DevOps picks up SARIF files from the `CodeAnalysisLogs` artifact automatically and surfaces them in the Advanced Security alerts view.

## Validating SARIF Output

Verify your SARIF file conforms to the schema:

```bash
# Using the SARIF multitool (npm package)
npx @microsoft/sarif-multitool validate results.sarif
```

KubeVigil references the official OASIS schema (`sarif-schema-2.1.0.json`) in every output file.

## See Also

- [Output Formats](../scanning/output-formats.md) -- all 8 supported formats
- [JUnit Integration](junit.md) -- CI/CD test result integration
- [IDE Integration](ide.md) -- editor workflows
- [Exit Codes](../reference/exit-codes.md) -- scan and fix exit codes
