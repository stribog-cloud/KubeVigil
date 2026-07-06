---
title: "KubeVigil Testing Strategy"
created: 2026-07-02
updated: 2026-07-02
type: project/testing-strategy
status: governing-reference
tags: [charter, governance, kubevigil, testing, tdd]
project: kubevigil
version: "1.1.0"
revision: 2
last_updated: 2026-07-02
parent_moc: "[[MOC - KubeVigil Governance]]"
owners: [maintainers (@msambare)]
---

# KubeVigil Testing Strategy

## 0. TL;DR

| Property | Value |
|----------|-------|
| Methodology | Test-Driven Development (red → green → refactor) |
| Coverage floor | 96% on `internal/` + `cmd/` |
| Critical path floor | 98% on `internal/fix/`, `internal/mcp/`, `internal/checker/secrets/` |
| Framework | Go `testing` + testify assertions |
| E2E | Bats (`test/e2e/`), optional Kind clusters |
| CI enforcement | `.github/workflows/ci.yml` mirrors `make all` |

KubeVigil validates 150 security checks, 8 report formats, and a YAML-preserving fix engine. Tests are the primary design tool: checkers are table-driven with 15+ cases; contract tests enforce the `Checker` seam; golden files lock output stability.

## 1. Guiding Principles

1. **Pyramid:** heavy unit tests, moderate integration, lean e2e.
2. **Contract backbone:** every registered checker passes `test/integration/contract_test.go`.
3. **Shift-left:** race detector, lint, vet, secrets scan, vuln scan on every change.
4. **Fixture-first:** `test/fixtures/<check-id>/` for scan; `test/fixtures/fix/` for fix round-trips.
5. **TDD mandatory:** bug fixes start with a failing reproduction test.

## 2. TDD Cycle

1. Write failing test (unit, integration, or golden).
2. Observe failure in CI or local run.
3. Minimal implementation to green.
4. Refactor with tests passing.

AI-assisted work must show observable failure before implementation (AI Agent Execution Standard §3.1).

## 3. Test Layers

### 3.1 Unit

- Location: `*_test.go` adjacent to production code
- Pattern: table-driven, 15+ cases for checkers
- Catches: logic errors, edge cases, regression per component

### 3.2 Contract

- Location: `test/integration/contract_test.go`
- Catches: registry drift, interface violations on new checkers

### 3.3 Golden

- Location: `test/golden/*`
- Catches: unintended output format changes (SARIF, HTML, etc.)

### 3.4 Integration

- Location: `test/integration/`
- Catches: scan/fix pipeline wiring, config exemptions, manifest workflows

### 3.5 End-to-end

- Location: `test/e2e/` (Bats)
- Catches: CLI UX, real binary behavior; optional against Kind

### 3.6 Benchmark

- Location: `*_bench_test.go`
- Catches: performance regressions on scan hot paths

## 4. Coverage Policy

### Measurement boundary

Coverage is measured on **shipped production code only**: all packages under `internal/` and `cmd/`. This boundary reflects what operators and integrators receive in the binary and MCP server — not test harnesses, fixtures, or golden generators.

### Excluded paths (principled, not number-driven)

| Path | Rationale |
|------|-----------|
| `test/` | Fixtures, contract harnesses, and e2e scripts are exercised by integration and Bats layers; including them would dilute the signal on production packages and reward vacuous helper coverage |
| Generated artifacts | None currently; if introduced, excluded per Charter §5.4 governance-change rule |

The exclusion is **not** drawn to hit a coverage target. Integration tests in `test/integration/` remain mandatory (`TestAllCheckersContract`, fix pipelines) and run on every `make test` / CI test job. The 96% floor applies to production packages because that is the trust surface; helper coverage is enforced by layer-specific gates instead of aggregate percentage.

`make coverage` fails below 96%. Per-package gaps on critical paths (`internal/fix/`, `internal/mcp/`, `internal/checker/secrets/`) are tracked at 98% even when aggregate passes.

## 5. Security Testing

Beyond unit tests:

- Path traversal and symlink rejection (`internal/mcp`, `internal/fix`)
- YAML bomb limits (document count, file size)
- MCP input validation tests in `internal/mcp/e2e_test.go`

See `docs/governance/threat-model.md` for threat-to-test mapping.

## 6. Local and CI Gates

Local: `make all`

CI: lint → test (96% coverage) → build → vulncheck; secrets-scan parallel

Gates must match (Engineering Charter §7.3).

## 7. Revision History

| Version | Revision | Date | Change |
|---------|----------|------|--------|
| 1.0.0 | 1 | 2026-07-02 | Initial testing strategy for charter compliance program. |
| 1.1.0 | 2 | 2026-07-02 | Expanded §4 with principled internal/+cmd boundary justification (audit F19). |