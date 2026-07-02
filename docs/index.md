# KubeVigil Documentation

**Know your clusters before attackers do.**

KubeVigil is a Kubernetes Security Posture Management (KSPM) CLI tool that scans clusters and manifests for security misconfigurations, maps findings to compliance frameworks, and auto-remediates fixable issues.

Documentation follows the [Diátaxis](https://diataxis.fr/) model:

| Quadrant | Purpose | Sections |
|----------|---------|----------|
| Tutorial | Learn by doing | [Quick Start](getting-started/quickstart.md) |
| How-to | Solve specific tasks | [Scanning](scanning/), [Auto-Remediation](auto-fix/), [Configuration](configuration/) |
| Reference | Facts and contracts | [CLI Reference](reference/), [Checks](checks/) |
| Explanation | Concepts and context | [Core Concepts](getting-started/concepts.md), [Compliance](compliance/) |

Governance and contributor docs: `docs/governance/`, `docs/dev/`, [Contributing](contributing/guide.md).

## Quick Links

- [Installation](getting-started/installation.md)
- [Quick Start](getting-started/quickstart.md)
- [CLI Reference](reference/cli-reference.md)

## Documentation Sections

### Getting Started

- [Installation](getting-started/installation.md) — Install KubeVigil from source or binary
- [Quick Start](getting-started/quickstart.md) — Your first scan in 5 minutes
- [Core Concepts](getting-started/concepts.md) — Checks, severity, categories, and scan modes

### Security Checks

- [Checks Overview](checks/overview.md) — All 110 checks at a glance
- Category references: [Workload](checks/workload.md) · [Image](checks/image.md) · [RBAC](checks/rbac.md) · [Secrets](checks/secrets.md) · [Network](checks/network.md) · [Pod Security Standards](checks/psa.md) · [Scheduling](checks/scheduling.md) · [Storage](checks/storage.md) · [Cluster Config](checks/cluster.md) · [Supply Chain](checks/supply-chain.md) · [Cloud Provider](checks/cloud.md) · [CRD](checks/crd.md)

### Scanning

- [Live Cluster Scanning](scanning/live-cluster.md) — Scan a running cluster
- [Manifest Scanning](scanning/manifest-scanning.md) — Scan YAML files and directories
- [Output Formats](scanning/output-formats.md) — Text, JSON, YAML, Markdown, HTML, SARIF, JUnit, CSV

### Auto-Remediation

- [Fix Overview](auto-fix/overview.md) — How auto-fix works
- [Safety Model](auto-fix/safety-model.md) — Five-ring safeguard model
- [Risk Levels](auto-fix/risk-levels.md) — Safe, moderate, aggressive
- [Backup & Restore](auto-fix/backup-restore.md) — Mandatory backup system
- [Output Modes](auto-fix/output-modes.md) — Diff, kubectl, Helm values, Kustomize, GitOps

### Compliance

- [Framework Overview](compliance/overview.md) — Supported frameworks
- [CIS Kubernetes Benchmark](compliance/cis.md) — v1.8 mapping
- [MITRE ATT&CK](compliance/mitre.md) — v14 mapping
- [NSA/CISA Hardening Guide](compliance/nsa.md) — v1.2 mapping

### Configuration

- [Configuration File](configuration/config-file.md) — `.kubevigil.yaml` reference
- [Exemptions](configuration/exemptions.md) — Excluding resources, namespaces, and checks
- [Tuning](configuration/tuning.md) — Concurrency, severity thresholds, and performance

### Reference

- [CLI Reference](reference/cli-reference.md) — All commands and flags
- [Exit Codes](reference/exit-codes.md) — Scan and fix exit codes
- [Glossary](reference/glossary.md) — Key terms

### Integrations

- [SARIF (GitHub/VS Code)](integrations/sarif.md) — Code scanning integration
- [JUnit (CI/CD)](integrations/junit.md) — Test result integration
- [IDE Integration](integrations/ide.md) — Editor workflows

### AI Assistant Integration

- [MCP Setup](mcp-setup.md) — Connect KubeVigil to AI assistants via the Model Context Protocol

### More

- [Troubleshooting](troubleshooting/common-issues.md) — Common issues and solutions
- [Architecture](architecture/overview.md) — Internal design overview
- [Contributing](contributing/guide.md) — How to contribute
