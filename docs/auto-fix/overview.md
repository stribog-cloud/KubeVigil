# Auto-Fix Overview

The `kubevigil fix` command scans Kubernetes manifests, identifies fixable security findings, and generates patched YAML with the issues resolved. It is a manifest-only command -- it never modifies a live cluster.

## What It Does

The fix engine runs the same security checks as `kubevigil scan`, then applies automated patches for findings that have a registered fix strategy. 20 of the 110 checks have auto-fix strategies. The remaining checks either require manual intervention (RBAC restructuring, NetworkPolicy creation) or involve changes too context-dependent to automate safely.

## YAML Round-Trip Preservation

KubeVigil patches YAML using the `yaml.v3` Node API, which preserves:

- **Comments**: Inline and block comments survive patching unchanged
- **Key ordering**: Keys stay in their original order
- **Indentation**: Original indentation style is maintained
- **Quoting**: Quoted strings remain quoted the same way

This means the diff between original and patched files shows only the security-relevant changes, making reviews straightforward.

## Dry-Run by Default

Running `kubevigil fix` without `--apply` shows what would change without modifying any files:

```bash
# Preview fixes (dry-run) -- no files are modified
kubevigil fix ./manifests/
```

This prints a unified diff of all planned changes and a summary table showing how many fixes would be applied at the current risk level.

## Applying Fixes

Add `--apply` to write the patched files to disk:

```bash
# Apply fixes to disk
kubevigil fix ./manifests/ --apply
```

Every `--apply` operation creates a mandatory backup before modifying any files. See [Backup and Restore](backup-restore.md) for details.

## Fix Pipeline

The fix engine operates as a pipeline with these stages:

1. **Scan**: Run all security checks against the target manifests
2. **Filter**: Select findings that have registered fix strategies, respecting `--checks`, `--severity`, `--namespace`, `--exclude-namespace`, and `--fingerprint` filters
3. **Classify**: Evaluate each finding against the safety classifier -- system namespace protection, known workload detection, risk level gating
4. **Gate**: Apply risk level filtering (`--risk-level safe|moderate|aggressive`)
5. **Plan**: Build the fix plan with unified diffs for each modified file
6. **Backup**: Create a backup of all files that will be modified (when `--apply` is used)
7. **Patch**: Write patched YAML to disk using the Node API round-trip engine
8. **Verify**: Optionally re-scan patched files to confirm findings are resolved (when `--verify` is used)

## 20 Auto-Fixable Checks

| Safety | Count | Checks |
|--------|-------|--------|
| Safe | 7 | `privileged`, `privilege-escalation`, `host-pid`, `host-ipc`, `proc-mount`, `share-process-namespace`, `automount-token` |
| Likely Safe | 9 | `capabilities-added`, `capabilities-not-dropped`, `run-as-root`, `read-only-rootfs`, `host-network`, `seccomp-profile`, `image-pull-policy`, `psa-labels-missing`, `psa-mode-audit-only` |
| Potentially Breaking | 4 | `resource-limits-missing`, `resource-requests-missing`, `ephemeral-storage-limits`, `host-ports` |

See [Risk Levels](risk-levels.md) for what each safety classification means.

## No Live Cluster Patching

The fix command generates artifacts only. It never executes `kubectl` commands, never connects to a cluster, and never modifies running workloads. The generated outputs (patched YAML, kubectl commands, Helm values, Kustomize overlays) must be applied through your normal deployment workflow.

## Command Reference

```bash
kubevigil fix [path] [flags]
```

### Execution Control

| Flag | Default | Description |
|------|---------|-------------|
| `--apply` | `false` | Actually modify files (default: dry-run) |
| `--yes` | `false` | Skip interactive confirmation |
| `--verify` | `false` | Re-scan after applying fixes |

### Risk Control

| Flag | Default | Description |
|------|---------|-------------|
| `--risk-level` | `safe` | Risk level: `safe`, `moderate`, `aggressive` |
| `--i-understand-system-namespaces` | `false` | Allow fixing resources in system namespaces |

### Filtering

| Flag | Description |
|------|-------------|
| `--checks` | Comma-separated check IDs to fix |
| `--severity` | Comma-separated severity levels to fix |
| `-n`, `--namespace` | Comma-separated namespaces to include |
| `--exclude-namespace` | Comma-separated namespaces to exclude |
| `--exclude-infra` | Exclude infrastructure namespaces |
| `--fingerprint` | Comma-separated finding fingerprints to fix |

### Output Control

| Flag | Default | Description |
|------|---------|-------------|
| `-o`, `--output` | `diff` | Output mode: `diff`, `kubectl`, `helm-values` |
| `--kustomize` | | Path for Kustomize overlay output |
| `--report` | | Custom path for fix report |
| `--backup-dir` | | Custom backup directory |

### Git Integration

| Flag | Description |
|------|-------------|
| `--git-pr` | Create branch and PR (requires `gh` or `glab` CLI) |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Fix successful -- all planned fixes applied (or dry-run shows changes) |
| `1` | Fix applied but `--verify` found remaining findings |
| `2` | Fix error -- total failure |
| `3` | Configuration error |
| `4` | No fixable findings found |
| `5` | Partial success -- some fixes applied but some files failed |

## Related Documentation

- [Safety Model](safety-model.md) -- the Five-Ring Safeguard Model
- [Risk Levels](risk-levels.md) -- what each check fixes and at which risk level
- [Backup and Restore](backup-restore.md) -- mandatory backup system
- [Output Modes](output-modes.md) -- diff, kubectl, Helm, Kustomize, report, GitOps
