# Safety Model

KubeVigil's auto-fix engine is built around a Five-Ring Safeguard Model. The design principle is simple: **an ignorant user who runs `kubevigil fix --apply` must not break their cluster.**

Every ring is a layer of protection. An unsafe fix must pass through all five rings before it can modify a file.

## The Five Rings

### Ring 1: Dry-Run by Default

The most important safeguard is the default behavior. Running `kubevigil fix` without `--apply` modifies nothing. It shows a diff of what would change and exits.

```bash
# This modifies NOTHING -- it is a preview
kubevigil fix ./manifests/
```

Output includes a unified diff and a summary:

```
KubeVigil Fix Summary
---------------------
Files scanned:       12
Files to modify:      4
Findings total:       9

By risk classification:
  Safe:                  5  [will be applied]
  Likely safe:           3  [skipped -- use --risk-level moderate]
  Potentially breaking:  1  [skipped -- use --risk-level aggressive]

This was a dry-run. No files were modified.
To apply these fixes: kubevigil fix ./manifests/ --apply
```

### Ring 2: Safety Classification

When `--apply` is used, only fixes classified as **Safe** are applied by default. Higher-risk fixes require explicit opt-in via `--risk-level`:

| Flag | What Gets Applied |
|------|-------------------|
| `--apply` | Safe only (zero-risk fixes) |
| `--apply --risk-level moderate` | Safe + Likely Safe |
| `--apply --risk-level aggressive` | Safe + Likely Safe + Potentially Breaking |

Risk levels are additive. `moderate` includes everything `safe` does plus more. `aggressive` includes everything.

**Manual Only** fixes are never auto-applied regardless of risk level. They appear in the fix report with guidance for manual remediation.

See [Risk Levels](risk-levels.md) for the complete list of checks and their classifications.

### Ring 3: System Namespace Hard Block

Resources in system namespaces are never auto-fixed, even with `--apply --risk-level aggressive`. This protects core cluster infrastructure from accidental breakage.

Protected namespaces include:

- **Kubernetes core**: `kube-system`, `kube-public`, `kube-node-lease`
- **CNI plugins**: `calico-system`, `calico-apiserver`, `tigera-operator`, `cilium`, `cilium-system`
- **Storage**: `rook-ceph`, `rook-ceph-system`, `longhorn-system`, `openebs`
- **Ingress**: `ingress-nginx`, `traefik`, `traefik-system`
- **Service mesh**: `istio-system`, `linkerd`, `linkerd-cni`
- **Monitoring**: `monitoring`, `prometheus`, `grafana`
- **PKI**: `cert-manager`
- **Load balancing**: `metallb-system`

To fix resources in these namespaces, you must pass the intentionally long flag:

```bash
kubevigil fix ./manifests/ --apply --i-understand-system-namespaces
```

The flag name is deliberately verbose. It forces the user to acknowledge the risk. You can extend the protected namespace list in `.kubevigil.yaml`:

```yaml
fix:
  additional_system_namespaces:
    - my-critical-ns
    - custom-operator-ns
```

### Ring 4: Interactive Confirmation

When `--apply` would modify more than 10 files (the bulk threshold), KubeVigil prompts for confirmation:

```
This will modify 23 files.

  Fixes to apply: 47
  Namespaces affected: default, production, staging

Apply 47 fixes? [y/N]
```

Pass `--yes` to bypass the prompt (required for CI environments):

```bash
kubevigil fix ./manifests/ --apply --yes
```

In non-interactive environments (CI detected via `CI=true`, `GITHUB_ACTIONS=true`, `GITLAB_CI=true`, or `JENKINS_URL`), `--apply` without `--yes` is an error:

```
Error: --apply in non-interactive mode requires --yes flag
Hint: Run 'kubevigil fix ./manifests/' first to review changes, then add --yes for CI.
```

The bulk threshold is configurable:

```yaml
# .kubevigil.yaml
fix:
  bulk_threshold: 20
```

### Ring 5: Mandatory Backup

Every `--apply` operation creates a backup before modifying any files. There is no `--no-backup` flag. The backup includes the original files and a `RESTORE.md` with restore instructions.

```
Backup: ./manifests/.kubevigil-backup-20250115T103045

To restore: cp -r ./manifests/.kubevigil-backup-20250115T103045/* ./manifests/
```

See [Backup and Restore](backup-restore.md) for details.

## Known Workload Detection

Beyond namespace protection, KubeVigil detects known system workloads by their container images and flags them for extra caution. These workloads legitimately require elevated privileges that security checks would flag.

Detected workload categories:

| Category | Examples |
|----------|----------|
| CNI plugins | Calico, Cilium, Flannel, Weave |
| Storage operators | Rook-Ceph, Longhorn, OpenEBS, local-path-provisioner |
| Core components | kube-proxy, CoreDNS, etcd, API server, controller-manager, scheduler |
| Monitoring agents | Prometheus node-exporter, Grafana agent |
| Ingress controllers | ingress-nginx, Traefik |
| Service mesh | Istio proxy, Linkerd proxy |

When a known workload is detected, its fixes are skipped with a reason explaining why the workload needs elevated privileges:

```
Skipped:
  CNI plugin requires elevated privileges for network management:   2
  Storage operator requires privileged access for disk management:   1
```

## Helm and Kustomize Detection

KubeVigil automatically detects when manifests are managed by Helm (via `app.kubernetes.io/managed-by: Helm` labels or `helm.sh/` prefixed labels) or Kustomize (via the presence of `kustomization.yaml`). When detected, it prints a warning suggesting the appropriate output mode:

```
Warning: 3 file(s) contain Helm-managed resources.
Consider using --output helm-values instead of patching manifests directly.
  manifests/deployment.yaml
  manifests/service.yaml
  manifests/ingress.yaml
```

```
Warning: Kustomize configuration detected.
Consider using --kustomize <dir> to generate a Kustomize overlay instead.
  manifests/
```

This helps users avoid patching generated files that would be overwritten on the next Helm upgrade or Kustomize build.
