# CLI Reference

KubeVigil provides a command-line interface for scanning Kubernetes clusters and manifests for security misconfigurations, auto-remediating findings, evaluating custom CEL policies, gating on baseline drift, and listing available checks.

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
| `--policy-file` | | | Path to a custom CEL policy file or directory, evaluated alongside built-in checks (see [Custom Policies](../policies/custom-policies.md)) |
| `--baseline` | | | Path to a baseline file; findings are annotated `new`/`existing` against it (see [Baseline & Drift Detection](../policies/baseline-drift.md)) |
| `--save-baseline` | | | Write a baseline file from this scan's (filtered) findings and exit `0` |
| `--fail-on-new` | | `false` | Exit `1` only when findings are new relative to `--baseline`, ignoring the `--fail-on` severity threshold. Requires `--baseline`. |

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

# Evaluate custom CEL policies alongside built-in checks
kubevigil scan -f manifests/ --policy-file configs/example-policies.yaml

# Save a baseline from the current findings
kubevigil scan -f manifests/ --save-baseline baseline.json

# Compare against a baseline and gate CI on new findings only
kubevigil scan -f manifests/ --baseline baseline.json --fail-on-new
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

### `kubevigil policy`

Validate and inspect user-defined CEL security policies (see [Custom Policies](../policies/custom-policies.md)).

#### `kubevigil policy validate <file|dir>`

Load, structurally validate, and CEL-compile every policy in the given file or directory. Exits `0` if all policies are valid, `3` otherwise.

```bash
kubevigil policy validate configs/example-policies.yaml
kubevigil policy validate policies/
```

```console
$ kubevigil policy validate configs/example-policies.yaml
OK: 4 policies valid in configs/example-policies.yaml
```

#### `kubevigil policy list <file|dir>`

List the policies defined in a file or directory, with their resolved severity and category.

```bash
kubevigil policy list configs/example-policies.yaml
```

```console
$ kubevigil policy list configs/example-policies.yaml
ID                           SEVERITY   CATEGORY       NAME
require-team-label           Low        custom         Workload missing team label
disallow-latest-tag          Medium     image          Container uses floating :latest tag
disallow-hostpath-volumes    High       storage        Workload mounts a hostPath volume
min-replica-count            Low        custom         Deployment has fewer than 2 replicas

Total: 4 policies
```

---

### `kubevigil mcp-server`

Launch the KubeVigil Model Context Protocol (MCP) server over stdin/stdout, so AI assistants (Claude Desktop, Cursor, VS Code, Claude Code) can scan clusters, query findings, and get remediation guidance through natural conversation.

```bash
kubevigil mcp-server [flags]
```

#### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--transport` | `stdio` | Transport type (currently only `stdio` is supported) |
| `--workspace-root` | | Root directory for manifest scans (default: `KUBEVIGIL_WORKSPACE_ROOT` env var or the process working directory) |

`--config` from the [global flags](#global-flags) is also honored, so the MCP server can load the same `.kubevigil.yaml` used by `scan` and `fix`.

If neither `--workspace-root` nor `KUBEVIGIL_WORKSPACE_ROOT` is set, the server falls back to its current working directory and logs a warning — set one of them explicitly for narrow path confinement of manifest scans.

#### Examples

```bash
# Start the MCP server with defaults (stdio transport, cwd as workspace root)
kubevigil mcp-server

# Confine manifest scans to a specific workspace directory
kubevigil mcp-server --workspace-root /path/to/manifests

# Use a custom configuration file
kubevigil mcp-server --config /path/to/.kubevigil.yaml
```

See [MCP Setup](../mcp-setup.md) for full AI assistant integration instructions, including Claude Desktop, Cursor, and VS Code configuration.

---

### `kubevigil version`

Print version information including the version string, git commit hash, and build date.

```bash
kubevigil version
```

Example output:

```
KubeVigil v1.0.0
  Commit: abc1234
  Built:  2026-07-06T12:00:00Z
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
