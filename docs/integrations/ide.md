# IDE Integration

KubeVigil integrates with code editors through SARIF output, task runners, and pre-commit hooks. This page covers workflows for getting scan results directly in your editor as you work on Kubernetes manifests.

## VS Code with SARIF Viewer

The fastest path to inline findings in VS Code is the SARIF Viewer extension.

### Setup

1. Install the [SARIF Viewer](https://marketplace.visualstudio.com/items?itemName=MS-SarifVSCode.sarif-viewer) extension.
2. Generate a SARIF file from your manifests:
   ```bash
   kubevigil scan -f ./k8s/ -o results.sarif
   ```
3. Open `results.sarif` in VS Code. The extension parses the file and displays findings as inline annotations alongside your manifest files.

### Watch Mode Workflow

Re-run the scan automatically when you save a manifest file. Add a VS Code task in `.vscode/tasks.json`:

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "KubeVigil Scan",
      "type": "shell",
      "command": "kubevigil scan -f ${workspaceFolder}/k8s/ -o ${workspaceFolder}/results.sarif",
      "group": "test",
      "presentation": {
        "reveal": "silent"
      },
      "problemMatcher": []
    }
  ]
}
```

Trigger it manually with **Ctrl+Shift+P > Tasks: Run Task > KubeVigil Scan**, or bind it to a keyboard shortcut for rapid feedback.

For automatic re-scanning on save, pair with the [Run on Save](https://marketplace.visualstudio.com/items?itemName=emeraldwalk.RunOnSave) extension:

```json
{
  "emeraldwalk.runonsave": {
    "commands": [
      {
        "match": "\\.ya?ml$",
        "cmd": "kubevigil scan -f ${workspaceFolder}/k8s/ -o ${workspaceFolder}/results.sarif"
      }
    ]
  }
}
```

Every time you save a `.yaml` or `.yml` file, KubeVigil re-scans and the SARIF Viewer updates inline annotations.

## JetBrains IDEs (IntelliJ, GoLand)

JetBrains IDEs do not have native SARIF support, but you can use an external tool configuration:

1. Go to **Settings > Tools > External Tools > Add**.
2. Configure:
   - **Program:** `kubevigil`
   - **Arguments:** `scan -f $ProjectFileDir$/k8s/ -o $ProjectFileDir$/results.sarif`
   - **Working directory:** `$ProjectFileDir$`
3. Run from **Tools > External Tools > KubeVigil Scan**.

View the SARIF output in the terminal panel or open `results.sarif` as JSON.

## Makefile Integration

A `Makefile` target gives a consistent entry point across editors and terminals:

```makefile
.PHONY: scan scan-sarif scan-fix

scan:
	kubevigil scan -f ./k8s/

scan-sarif:
	kubevigil scan -f ./k8s/ -o results.sarif

scan-fix:
	kubevigil fix ./k8s/
```

Run from any editor's integrated terminal:

```bash
make scan-sarif
```

## Task Runner Integration

### Just (justfile)

```just
scan:
    kubevigil scan -f ./k8s/

scan-sarif:
    kubevigil scan -f ./k8s/ -o results.sarif

fix-preview:
    kubevigil fix ./k8s/

fix-apply:
    kubevigil fix ./k8s/ --apply --risk-level moderate
```

### npm scripts (package.json)

For projects that already use npm:

```json
{
  "scripts": {
    "scan": "kubevigil scan -f ./k8s/",
    "scan:sarif": "kubevigil scan -f ./k8s/ -o results.sarif",
    "scan:ci": "kubevigil scan -f ./k8s/ -o junit --fail-on high > kubevigil-results.xml"
  }
}
```

## Pre-Commit Hook

Scan changed manifests before each commit to catch issues early. Create `.git/hooks/pre-commit` (or use [pre-commit framework](https://pre-commit.com/)):

```bash
#!/usr/bin/env bash
set -euo pipefail

# Find staged YAML files in the k8s directory.
STAGED=$(git diff --cached --name-only --diff-filter=ACM -- 'k8s/*.yaml' 'k8s/*.yml')

if [ -z "$STAGED" ]; then
  exit 0
fi

echo "Running KubeVigil on staged manifests..."

# Scan each staged file individually.
FAILED=0
for file in $STAGED; do
  if ! kubevigil scan -f "$file" --fail-on high --severity high -o text > /dev/null 2>&1; then
    echo "KubeVigil: high/critical findings in $file"
    kubevigil scan -f "$file" --severity high
    FAILED=1
  fi
done

if [ "$FAILED" -eq 1 ]; then
  echo ""
  echo "Commit blocked: fix high/critical findings or use 'git commit --no-verify' to bypass."
  exit 1
fi
```

Make it executable:

```bash
chmod +x .git/hooks/pre-commit
```

### With the pre-commit Framework

Add to `.pre-commit-config.yaml`:

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
        args: ['--fail-on', 'high', '--severity', 'high']
```

## Scan a Single File

During development, scan the file you are editing rather than the entire directory:

```bash
kubevigil scan -f deployment.yaml
```

This is faster and produces only the findings relevant to the file you are working on. Combine with the fix preview to see what changes KubeVigil would make:

```bash
kubevigil fix deployment.yaml
```

## See Also

- [SARIF Integration](sarif.md) -- SARIF output details and GitHub Code Scanning
- [JUnit Integration](junit.md) -- CI/CD test result integration
- [Quick Start](../getting-started/quickstart.md) -- first scan in under a minute
- [Output Formats](../scanning/output-formats.md) -- all 8 supported formats
