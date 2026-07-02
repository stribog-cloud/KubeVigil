---
title: "Public Surface Map"
audience: consumer, embedder, contributor
created: 2026-07-02
type: project/public-surface
status: reference
---

# KubeVigil Public Surface Map

Stable contracts for integrators and contributors. Breaking changes require ADR + deprecation entry in `docs/dev/deprecations.md`.

## CLI commands

| Command | Stability | Notes |
|---------|-----------|-------|
| `scan` | stable | Live and manifest modes |
| `fix` | stable | Dry-run default |
| `list` | stable | Subcommand `checks` |
| `version` | stable | |
| `mcp-server` | stable | stdio MCP transport |

## MCP tools

| Tool | Stability |
|------|-----------|
| `kubevigil_scan` | stable |
| `kubevigil_get_findings` | stable |
| `kubevigil_get_summary` | stable |

## Checker interface

Package `github.com/stribog-cloud/kubevigil/internal/checker`:

- `Checker` interface (`Name`, `Description`, `Categories`, `SupportedModes`, `RequiredResources`, `Run`)
- `Finding`, `FixHint`, `Registry`, `ResourceCache`

**110** registered checks as of v0.5.0.

## Report formats

`text`, `json`, `yaml`, `markdown`, `html`, `sarif`, `junit`, `csv`

## Configuration

`.kubevigil.yaml` schema documented in `docs/configuration/config-file.md`.

## Versioning

Semantic versioning. Compatibility window: one minor version for CLI flags and output schemas.