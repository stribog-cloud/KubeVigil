---
title: "Architecture for Contributors"
audience: contributor
created: 2026-07-02
type: project/dev-architecture
status: reference
---

# Architecture for Contributors

Derived from `docs/governance/MASTER-REFERENCE.md`. Read the master reference for authoritative design; this document is the contributor-oriented view.

## Repository layout

| Path | Purpose |
|------|---------|
| `cmd/kubevigil/` | Cobra CLI — thin transport layer |
| `internal/checker/` | `Checker` interface + 12 category packages |
| `internal/engine/` | Scan orchestration |
| `internal/fix/` | Auto-remediation, YAML patcher |
| `internal/report/` | Eight output formatters |
| `internal/mcp/` | MCP stdio server tools |
| `test/fixtures/` | Scan/fix YAML fixtures |
| `test/integration/` | Contract and pipeline tests |
| `test/golden/` | Stable report outputs |

## Boundaries to respect

- Checkers read only from `ResourceCache` — no direct API calls
- Fix engine never calls Kubernetes write APIs
- Reporters consume `checker.ScanResult` only
- MCP tools delegate to the same engine/fix paths as CLI

## Build and test entrypoints

```bash
make all          # full gate set
make test         # race-enabled unit/integration
go test ./test/integration/ -run TestCheckerContract
```

## Common pitfalls

- Registering a checker without a blank import in `cmd/kubevigil/scan.go`
- Using `yaml.Marshal` in fix code (breaks comment preservation)
- Date-sensitive fixtures — use recent timestamps or rotation annotations

## ADRs

Design history: `docs/governance/adr/`