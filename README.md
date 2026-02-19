# KubeVigil

![Coverage](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/msambare/1248dd902276859b5cdea636aa5ba175/raw/kubevigil-coverage.json)

**Know your clusters before attackers do.**

KubeVigil is a Kubernetes Security Posture Management (KSPM) CLI tool that
scans clusters and YAML manifests for security misconfigurations. It runs
**110 security checks** across **12 categories**, maps every finding to
industry compliance frameworks (CIS Kubernetes Benchmark, MITRE ATT&CK,
NSA/CISA), and outputs reports in 8 formats — from colored terminal text to
SARIF for GitHub Security.

## Why KubeVigil

- **Single binary, zero dependencies.** No agents, no sidecars, no cluster
  components to install.
- **110 checks, 12 categories.** Workload security, RBAC, network policies,
  secrets, Pod Security Standards, scheduling, storage, cluster config, supply
  chain, cloud provider, and CRD security.
- **Dual-mode scanning.** Scan live clusters or static YAML manifests.
- **Compliance mapping.** CIS v1.8, MITRE ATT&CK v14, NSA/CISA v1.2.
- **8 output formats.** Text, JSON, Markdown, HTML, SARIF, YAML, JUnit, CSV.
- **Auto-remediation.** `kubevigil fix` patches manifests with comment-preserving
  YAML edits and a five-ring safety model.
- **CI-ready exit codes.** Clean integration with any CI/CD pipeline.

## Quick Start

```bash
# Install
go install github.com/stribog-cloud/kubevigil/cmd/kubevigil@latest

# Scan manifests (no cluster needed)
kubevigil scan -f ./manifests/

# Scan a live cluster
kubevigil scan

# Filter by severity
kubevigil scan --severity high

# Output as HTML report
kubevigil scan -f ./manifests/ -o report.html

# Preview auto-fixes (dry-run)
kubevigil fix ./manifests/

# Apply safe fixes
kubevigil fix ./manifests/ --apply
```

See the [Quick Start guide](docs/getting-started/quickstart.md) for more examples.

## Documentation

Full documentation lives in [`docs/`](docs/index.md):

| Section | Description |
|---------|-------------|
| [Getting Started](docs/getting-started/installation.md) | Installation, quickstart, core concepts |
| [Security Checks](docs/checks/overview.md) | All 110 checks across 12 categories |
| [Scanning](docs/scanning/live-cluster.md) | Live cluster and manifest scanning |
| [Output Formats](docs/scanning/output-formats.md) | Text, JSON, HTML, SARIF, and 4 more |
| [Auto-Remediation](docs/auto-fix/overview.md) | Fix engine, safety model, risk levels |
| [Compliance](docs/compliance/overview.md) | CIS, MITRE ATT&CK, NSA/CISA mappings |
| [Configuration](docs/configuration/config-file.md) | `.kubevigil.yaml`, exemptions, tuning |
| [CLI Reference](docs/reference/cli-reference.md) | All commands and flags |
| [Integrations](docs/integrations/sarif.md) | SARIF, JUnit, IDE workflows |
| [Architecture](docs/architecture/overview.md) | Internal design for contributors |
| [Contributing](docs/contributing/guide.md) | How to add checks and fix strategies |
| [Troubleshooting](docs/troubleshooting/common-issues.md) | Common issues and solutions |

## Security Checks (110 total)

| Category | Checks | Examples |
|----------|--------|---------|
| [Workload](docs/checks/workload.md) | 24 | `privileged`, `host-pid`, `run-as-root`, `resource-limits-missing` |
| [Image](docs/checks/image.md) | 9 | `image-tag-latest`, `image-registry-blocklist` |
| [RBAC](docs/checks/rbac.md) | 15 | `rbac-wildcard-verbs`, `rbac-cluster-admin`, `automount-token` |
| [Secrets](docs/checks/secrets.md) | 7 | `secrets-in-env`, `secrets-unencrypted`, `secrets-in-configmap` |
| [Network](docs/checks/network.md) | 12 | `network-policy-missing`, `ingress-no-tls`, `external-ips` |
| [PSA](docs/checks/psa.md) | 6 | `psa-labels-missing`, `psa-baseline-violations` |
| [Scheduling](docs/checks/scheduling.md) | 8 | `toleration-control-plane`, `pod-disruption-budget` |
| [Storage](docs/checks/storage.md) | 5 | `pvc-no-encryption`, `emptydir-size-limit` |
| [Cluster](docs/checks/cluster.md) | 10 | `etcd-encryption`, `api-server-anonymous`, `deprecated-api-usage` |
| [Supply Chain](docs/checks/supply-chain.md) | 6 | `container-runtime-socket`, `liveness-readiness-probes` |
| [Cloud](docs/checks/cloud.md) | 4 | `eks-imds-access`, `gke-metadata-concealment` |
| [CRD](docs/checks/crd.md) | 4 | `crd-validation-missing`, `cert-manager-expiry` |

See [Checks Overview](docs/checks/overview.md) for the full list with severities, modes, and auto-fix status.

## Auto-Remediation

20 checks support automatic fixing with a five-ring safety model:

```bash
kubevigil fix ./manifests/                              # Dry-run (preview)
kubevigil fix ./manifests/ --apply                      # Safe fixes only
kubevigil fix ./manifests/ --apply --risk-level moderate # + Likely Safe
kubevigil fix ./manifests/ --apply --verify             # Fix + re-scan
kubevigil fix ./manifests/ --kustomize ./overlay/       # Kustomize output
kubevigil fix ./manifests/ -o kubectl                   # kubectl commands
```

See [Auto-Fix Overview](docs/auto-fix/overview.md) and
[Safety Model](docs/auto-fix/safety-model.md) for details.

## Output Formats

| Format | Flag | Use Case |
|--------|------|----------|
| Text | `-o text` | Terminal output (default) |
| JSON | `-o json` | CI pipelines, jq processing |
| HTML | `-o html` | Interactive dashboard report |
| SARIF | `-o sarif` | GitHub Security, VS Code |
| Markdown | `-o markdown` | PR comments |
| YAML | `-o yaml` | Kubernetes tooling |
| JUnit | `-o junit` | CI test reporting |
| CSV | `-o csv` | Spreadsheet analysis |

Write to file: `kubevigil scan -o report.html` (format inferred from extension).

## Exit Codes

| Code | Scan | Fix |
|------|------|-----|
| 0 | Clean | Fixes applied |
| 1 | Findings above threshold | Remaining findings after verify |
| 2 | Scan error | Total failure |
| 3 | Config error | Config error |
| 4 | — | Nothing to fix |
| 5 | — | Partial success |

See [Exit Codes](docs/reference/exit-codes.md) for CI/CD usage examples.

## Roadmap

- [x] **Phase 1** — Core engine, 25 workload checks, text/JSON output, CLI
- [x] **Phase 2** — 85 additional checks (110 total), 6 new formats, compliance mapping
- [x] **Phase 3** — Auto-remediation, 20 fixable checks, YAML round-trip, safety model
- [ ] **Phase 4** — GitHub Action, baseline management, PR decoration
- [ ] **Phase 5** — Admission webhooks, operator mode, Prometheus metrics
- [ ] **Phase 6** — Multi-cluster, trend analysis, Rego policies
- [ ] **Phase 7** — SDK, plugin system, Helm/Krew/Homebrew distribution

## Development

```bash
make build         # Build binary to ./bin/kubevigil
make test          # Run all tests with race detection
make lint          # Run golangci-lint
make check         # All quality gates (vet + lint + test)
```

See [Contributing Guide](docs/contributing/guide.md) for development setup
and how to add new checks.

## License

Apache 2.0 — See [LICENSE](LICENSE) for details.
