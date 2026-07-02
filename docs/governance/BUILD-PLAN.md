---
title: "KubeVigil Build Plan"
created: 2026-07-02
updated: 2026-07-02
type: project/build-plan
status: governing-reference
tags: [charter, governance, kubevigil, build-plan]
project: kubevigil
version: "1.0.0"
revision: 1
last_updated: 2026-07-02
---

# KubeVigil Build Plan

## 0. TL;DR

KubeVigil v0.5.0 completed Phase 3 (110 checks, auto-remediation). Current phase: **Charter Compliance** — bring the public repository into full Stribog canon compliance without rewriting stable scan/fix/MCP surfaces.

## Phase History

| Phase | Deliverable | Status |
|-------|-------------|--------|
| 1 | Core scan engine, checkers, text/json output | Complete |
| 2 | 8 output formats, compliance frameworks, config | Complete |
| 3 | 110 checks, fix engine, MCP server | Complete (v0.5.0) |
| 4 | Charter compliance (governance, gates, docs) | In progress |

## Phase 4 — Charter Compliance

### Acceptance criteria

- [x] Charter Compliance Annex filed with public release profile
- [x] Master reference, testing strategy, waiver register, ADRs, audit closeout
- [x] `make all` enforces 96% coverage and full gate set
- [x] CI mirrors `make coverage` and documentation gates
- [x] Developer and user doc gates (`doc-gate`, `doc-drift-gate`, `doc-samples-test`)
- [x] Threat model and security ADRs published
- [x] No regression in golden scan → fix → re-scan workflow

### Quality gates (phase closeout)

```bash
make all
make doc-gate
make doc-drift-gate
make doc-samples-test
```

### Dependencies

None blocking — documentation and gate wiring only; code changes limited to coverage and flaky-test fixes.

### Out of scope

- Rewriting checker registry or report HTML implementation
- New security checks beyond compliance-driven test coverage
- Hosted service / operational delivery artifacts