# CLI Reference

KubeVigil provides a command-line interface for scanning Kubernetes clusters and manifests for security misconfigurations, auto-remediating findings, and listing available checks.

## Global Flags

These flags are available on all commands:

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--config` | | auto-discover | Path to configuration file |
| `--output` | `-o` | `text` | Output format or file path (text, json, markdown, yaml, html, sarif, junit, csv; or a file path like report.html) |
| `--no-color` | | `false` | Disable colored output |
| `--verbose` | `-v` | `false` | Enable verbose (debug) logging |

## Commands

### `kubevigil scan`

Scan Kubernetes resources for security issues. Supports both live cluster scanning and manifest file scanning.

```bash
kubevigil scan [flags]
```

#### Scan Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--file` | `-f` | | Path to YAML file or directory (manifest mode) |
| `--kubeconfig` | | | Path to kubeconfig file |
| `--context` | | | Kubeconfig context to use |
| `--namespace` | `-n` | | Scan only this namespace |
| `--exclude-namespace` | | | Exclude this namespace from results |
| `--severity` | | | Minimum severity to report (info, low, medium, high, critical) |
| `--fail-on` | | | Minimum severity for exit code 1 (overrides config) |
| `--framework` | | | Filter findings by compliance framework (cis, mitre, nsa) |
| `--concurrency` | | | Max concurrent checks (overrides config) |
| `--include-managed` | | `false` | Include managed Pods and ReplicaSets |
| `--include-system-namespaces` | | `false` | Include system namespaces (kube-system, kube-public, kube-node-lease) |
| `--exclude-infra` | | `false` | Exclude infrastructure namespaces |
| `--no-aggregate` | | `false` | Show every finding individually instead of grouping |
| `--summary-only` | | `false` | Show only the summary table (text output only) |

#### Examples

```bash
# Scan a live cluster using the current kubeconfig context
kubevigil scan

# Scan a specific namespace
kubevigil scan -n production

# Scan manifest files
kubevigil scan -f manifests/

# Scan a single file with JSON output
kubevigil scan -f deployment.yaml -o json

# Scan with CIS framework filter and HTML report
kubevigil scan --framework cis -o report.html

# Scan with strict severity threshold for CI
kubevigil scan --fail-on medium --severity medium

# Scan a different kubeconfig context
kubevigil scan --kubeconfig ~/.kube/staging --context staging-cluster

# Summary only for quick overview
kubevigil scan --summary-only
```

#### Exit Codes

See [Exit Codes](exit-codes.md) for the complete table.

---

### `kubevigil fix`

Auto-remediate security findings in Kubernetes manifests. Scans the specified path, identifies fixable issues, and generates patched YAML.

```bash
kubevigil fix <path> [flags]
```

The `<path>` argument is required and must be a YAML file or directory.

#### Execution Control Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--apply` | `false` | Actually modify files (default is dry-run) |
| `--yes` | `false` | Skip interactive confirmation for bulk operations |
| `--verify` | `false` | Re-scan after applying fixes to confirm resolution |

#### Risk Control Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--risk-level` | `safe` | Risk level for fixes: `safe`, `moderate`, `aggressive` |
| `--i-understand-system-namespaces` | `false` | Allow fixing resources in system namespaces |

Risk levels are additive:

- `safe` -- only safe fixes (zero risk)
- `moderate` -- safe + likely safe fixes (very low risk)
- `aggressive` -- safe + likely safe + potentially breaking fixes

#### Filtering Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--checks` | | | Comma-separated check IDs to fix |
| `--severity` | | | Comma-separated severity levels to fix |
| `--namespace` | `-n` | | Comma-separated namespaces to include |
| `--exclude-namespace` | | | Comma-separated namespaces to exclude |
| `--exclude-infra` | | `false` | Exclude infrastructure namespaces |
| `--fingerprint` | | | Comma-separated finding fingerprints to fix |

#### Output Control Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--output` | `-o` | `diff` | Output mode: `diff`, `kubectl`, `helm-values` |
| `--kustomize` | | | Path for Kustomize overlay output |
| `--report` | | | Custom path for the fix report |
| `--backup-dir` | | | Custom backup directory |

#### Git Integration Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--git-pr` | `false` | Create a branch and pull request (requires `gh` or `glab`) |

#### Examples

```bash
# Dry-run: preview what would change
kubevigil fix manifests/

# Apply safe fixes
kubevigil fix manifests/ --apply

# Apply safe and likely-safe fixes
kubevigil fix manifests/ --apply --risk-level moderate

# Apply all auto-fixable issues
kubevigil fix manifests/ --apply --risk-level aggressive

# Fix only specific checks
kubevigil fix manifests/ --apply --checks privileged,privilege-escalation

# Generate kubectl patch commands instead of modifying files
kubevigil fix manifests/ -o kubectl

# Generate Helm security values
kubevigil fix manifests/ -o helm-values

# Generate Kustomize overlay
kubevigil fix manifests/ --kustomize overlays/security/

# Apply with verification
kubevigil fix manifests/ --apply --verify

# Apply in CI without interactive prompts
kubevigil fix manifests/ --apply --yes

# Apply and create a pull request
kubevigil fix manifests/ --apply --git-pr
```

#### Exit Codes

See [Exit Codes](exit-codes.md) for the complete table.

---

### `kubevigil list checks`

List all available security checks with their ID, category, supported scan modes, and description.

```bash
kubevigil list checks
```

Output includes:

- **ID**: The kebab-case check identifier (used in `--checks`, `checks.disabled`, annotations)
- **CATEGORY**: The check category (workload, image, rbac, network, etc.)
- **MODES**: Supported scan modes (Live, Manifest, or both)
- **DESCRIPTION**: What the check detects

---

### `kubevigil version`

Print version information including the version string, git commit hash, and build date.

```bash
kubevigil version
```

Example output:

```
KubeVigil v0.1.0
  Commit: abc1234
  Built:  2026-01-15T10:30:00Z
```

---

## Output Formats

KubeVigil supports 8 output formats for scan results. Specify the format with the `-o` flag:

| Format | Flag Value | Description |
|--------|-----------|-------------|
| Text | `text` | Human-readable table with color (default) |
| JSON | `json` | Machine-readable JSON |
| YAML | `yaml` | Machine-readable YAML |
| Markdown | `markdown` | Markdown tables |
| HTML | `html` | Interactive HTML report with dashboard |
| SARIF | `sarif` | Static Analysis Results Interchange Format |
| JUnit | `junit` | JUnit XML for CI test reporting |
| CSV | `csv` | Comma-separated values |

You can also specify a file path with an extension to auto-detect the format and write to the file:

```bash
kubevigil scan -o report.html    # HTML report written to report.html
kubevigil scan -o results.json   # JSON written to results.json
kubevigil scan -o findings.sarif # SARIF written to findings.sarif
```
