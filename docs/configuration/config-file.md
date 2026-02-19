# Configuration File

KubeVigil uses a YAML configuration file to control scan behavior, check selection, severity overrides, exemptions, and policy settings. All settings can be customized without changing command-line flags.

## File Location

KubeVigil auto-discovers configuration files in the following order:

1. `.kubevigil.yaml` in the current working directory
2. `~/.config/kubevigil/kubevigil.yaml`
3. `~/.kubevigil.yaml`

The first file found is used. To specify an explicit path, use the `--config` flag:

```bash
kubevigil scan --config path/to/config.yaml
```

## Full Annotated Example

```yaml
# Config file format version (required, must be "1")
version: "1"

# Global scan settings
settings:
  # Minimum severity to include in results.
  # Valid: info, low, medium, high, critical
  # Default: info
  severity_threshold: info

  # Minimum severity that causes a non-zero exit code (exit 1).
  # Valid: info, low, medium, high, critical
  # Default: high
  fail_on: high

  # Maximum number of checks to run in parallel.
  # Default: 10
  concurrency: 10

  # Maximum duration for the scan. Uses Go duration format.
  # Examples: "30s", "5m", "1h"
  # Default: 5m
  timeout: 5m

  # Include managed Pods and ReplicaSets in results.
  # Normally filtered to avoid duplicate findings from owner workloads.
  # Default: false
  include_managed: false

  # Include system namespaces (kube-system, kube-public, kube-node-lease).
  # Default: false
  include_system_namespaces: false

  # Exclude infrastructure namespaces (monitoring, rook-ceph, calico, etc.).
  # Default: false
  exclude_infra: false

  # Additional namespace names to classify as infrastructure.
  # These are added to the built-in list; they do not replace it.
  infra_namespaces:
    - my-infra-namespace

  # Disable finding aggregation. When false (default), findings with the
  # same check and message are grouped per namespace.
  # Default: false
  no_aggregate: false

# Check configuration
checks:
  # List of check IDs to skip entirely.
  disabled:
    - image-tag-latest
    - runtime-class

  # Per-check severity overrides.
  overrides:
    host-path-volumes:
      severity: critical
    resource-limits-missing:
      severity: low

# Exemptions for specific resources or namespaces.
# See docs/configuration/exemptions.md for details.
exemptions:
  - namespace: kube-system
    reason: "System namespace — elevated privileges expected"
    approved_by: "platform-team"
  - namespace: monitoring
    checks:
      - host-network
      - host-ports
    reason: "Prometheus needs host network for node metrics"
    approved_by: "sre-team"
    expires: "2026-12-31"

# Policy configuration for policy-based checks.
policies:
  images:
    # Allowed image registries (for the image-registry-allowlist check).
    allowed_registries:
      - gcr.io/my-project
      - docker.io/myorg
    # Blocked image registries (for the image-registry-blocklist check).
    blocked_registries:
      - docker.io/untrusted
    # Require images to be signed (for the image-signature-verification check).
    require_signatures: true
    # Require SBOM attestations (for the image-sbom-attestation check).
    require_sbom: false
    # Require provenance attestations (for the image-provenance check).
    require_provenance: false
  secrets:
    # Minimum Shannon entropy (bits/char) to flag as a potential secret.
    # Default: 4.5
    entropy_threshold: 4.5
    # Maximum age in days before a secret is considered stale.
    # Default: 90
    max_age_days: 90

# Fix command configuration.
fix:
  # Additional namespaces to protect from auto-fixing.
  # Added to the built-in system namespace list.
  additionalSystemNamespaces:
    - istio-system
    - cert-manager
  # Number of files above which interactive confirmation is required.
  # Default: 10
  bulkThreshold: 10
  # Default backup directory for fix operations.
  # CLI --backup-dir flag overrides this value.
  backupDir: ""
```

## Field Reference

### `version` (required)

The configuration file format version. Must be `"1"`. KubeVigil will reject configuration files with an unsupported version.

### `settings`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `severity_threshold` | string | `info` | Minimum severity to include in results. Findings below this threshold are filtered out. |
| `fail_on` | string | `high` | Minimum severity that triggers exit code 1. Used in CI to fail builds on high-severity findings. |
| `concurrency` | int | `10` | Maximum number of checks running in parallel. Increase for faster scans on large clusters; decrease to reduce API server load. |
| `timeout` | string | `5m` | Maximum scan duration in Go duration format (`30s`, `5m`, `1h`). |
| `include_managed` | bool | `false` | Include managed Pods and ReplicaSets. Normally filtered to avoid duplicate findings from Deployments/StatefulSets that own them. |
| `include_system_namespaces` | bool | `false` | Include kube-system, kube-public, and kube-node-lease namespaces in results. |
| `exclude_infra` | bool | `false` | Exclude infrastructure namespaces (monitoring, rook-ceph, calico, etc.) from results. |
| `infra_namespaces` | list | `[]` | Additional namespace names to classify as infrastructure. Additive to the built-in list. |
| `no_aggregate` | bool | `false` | Show every finding individually instead of grouping by check and namespace. |

### `checks`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `disabled` | list | `[]` | Check IDs to skip during scanning. Use `kubevigil list checks` to see all available IDs. |
| `overrides` | map | `{}` | Per-check overrides. Currently supports overriding `severity` for any check ID. |

### `exemptions`

See [Exemptions](exemptions.md) for detailed documentation.

### `policies`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `images.allowed_registries` | list | `[]` | Registries from which images are allowed. Used by the `image-registry-allowlist` check. |
| `images.blocked_registries` | list | `[]` | Registries from which images are blocked. Used by the `image-registry-blocklist` check. |
| `images.require_signatures` | bool | `false` | Require image signatures. Used by the `image-signature-verification` check. |
| `images.require_sbom` | bool | `false` | Require SBOM attestations. Used by the `image-sbom-attestation` check. |
| `images.require_provenance` | bool | `false` | Require provenance attestations. Used by the `image-provenance` check. |
| `secrets.entropy_threshold` | float | `4.5` | Minimum Shannon entropy to flag as a potential secret. |
| `secrets.max_age_days` | int | `90` | Maximum age in days before a secret is considered stale. |

### `fix`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `additionalSystemNamespaces` | list | `[]` | Namespaces to add to the system namespace protection list. Resources in these namespaces will not be auto-fixed unless `--i-understand-system-namespaces` is used. |
| `bulkThreshold` | int | `10` | Number of files above which interactive confirmation is required for `--apply`. |
| `backupDir` | string | `""` | Default backup directory for fix operations. Empty means auto-generated. |

## CLI Overrides

Command-line flags take precedence over configuration file values. The following flags override their config equivalents:

| CLI Flag | Config Field |
|----------|-------------|
| `--severity` | `settings.severity_threshold` |
| `--fail-on` | `settings.fail_on` |
| `--concurrency` | `settings.concurrency` |
| `--include-managed` | `settings.include_managed` |
| `--include-system-namespaces` | `settings.include_system_namespaces` |
| `--exclude-infra` | `settings.exclude_infra` |
| `--no-aggregate` | `settings.no_aggregate` |
| `--backup-dir` | `fix.backupDir` |
