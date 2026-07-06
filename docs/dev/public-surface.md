---
title: "Public Surface Map"
audience: consumer, embedder, contributor
created: 2026-07-02
updated: 2026-07-02
last_updated: 2026-07-02
aliases: [public-surface, api-surface, stable-contracts]
type: project/public-surface
status: design-reference
tags: [kubevigil, developer, api, mcp, cli]
version: "1.0.0"
revision: 1
project: kubevigil
parent_moc: "[[MOC - KubeVigil Developer Documentation]]"
owners: [maintainers (@msambare)]
---

# KubeVigil Public Surface Map

Stable contracts for integrators and contributors. Breaking changes require ADR + deprecation entry in `docs/dev/deprecations.md`.

## CLI commands

| Command | Stability | Notes |
|---------|-----------|-------|
| `scan` | stable | Live and manifest modes; `--policy-file`, `--baseline`, `--save-baseline`, `--fail-on-new` (v1.1.0) |
| `fix` | stable | Dry-run default |
| `list` | stable | Subcommand `checks` |
| `version` | stable | |
| `mcp-server` | stable | stdio MCP transport |
| `policy` | stable | Subcommands `validate`, `list` — custom CEL policies (v1.1.0) |
| `webhook` | stable | Validating admission webhook — real-time deny/warn (v1.2.0) |

## MCP tools

| Tool | Stability | Notes |
|------|-----------|-------|
| `scan_cluster` | stable | Live cluster scan |
| `scan_manifests` | stable | Manifest scan (workspace-confined) |
| `get_findings` | stable | Query last scan findings |
| `get_summary` | stable | Summary of last scan |
| `list_checks` | stable | Registered checker catalog |
| `get_remediation` | stable | Remediation hint for a finding |

## Checker interface

Package `github.com/stribog-cloud/kubevigil/internal/checker`:

- `Checker` interface (`Name`, `Description`, `Categories`, `SupportedModes`, `RequiredResources`, `Run`)
- `Finding`, `FixHint`, `Registry`, `ResourceCache`

**150** registered checks as of v1.3.0.

## Report formats

`text`, `json`, `yaml`, `markdown`, `html`, `sarif`, `junit`, `csv`

## Configuration

`.kubevigil.yaml` schema documented in `docs/configuration/config-file.md`.

## Versioning

Semantic versioning. Compatibility window: one minor version for CLI flags and output schemas.