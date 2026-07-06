---
title: "KubeVigil Build Plan"
created: 2026-07-02
updated: 2026-07-06
type: project/build-plan
status: governing-reference
tags: [charter, governance, kubevigil, build-plan]
project: kubevigil
version: "1.1.0"
revision: 2
last_updated: 2026-07-06
parent_moc: "[[MOC - KubeVigil Governance]]"
owners: [maintainers (@msambare)]
---

# KubeVigil Build Plan

## 0. TL;DR

KubeVigil v0.5.0 completed Phase 3 (110 checks, auto-remediation). Phase 4
(charter compliance) and Phase 5 (v1.0.0 production hardening and release
engineering) are complete: **v1.0.0 is the first stable release**, with
supply-chain-verified artifacts and a semver-stable public surface.

## Phase History

| Phase | Deliverable | Status |
|-------|-------------|--------|
| 1 | Core scan engine, checkers, text/json output | Complete |
| 2 | 8 output formats, compliance frameworks, config | Complete |
| 3 | 110 checks, fix engine, MCP server | Complete (v0.5.0) |
| 4 | Charter compliance (governance, gates, docs) | Complete |
| 5 | v1.0.0 hardening + release engineering | Complete (v1.0.0 released 2026-07-06) |

## Phase 5 — v1.0.0 Hardening & Release Engineering

### Engineering deliverables (complete)

- [x] Windows build restored + runtime-tested on a Windows CI runner (`windows-pathguard` job); TOCTOU residual precisely disclosed (threat model rev 5)
- [x] CI cross-compile gate for all 5 release targets + platform-tagged vet
- [x] Supply chain: SPDX SBOMs, keyless Cosign signature over checksums **and container images**, SLSA build provenance for archives **and images**, GHCR multi-arch images
- [x] Tag protection ruleset (signatures, no delete/force); release gate strengthened (vet + lint + govulncheck before publish)
- [x] Per-package coverage floor (96%) enforced in CI for `internal/fix`, `internal/mcp`, `internal/checker/secrets`
- [x] E2E suite (kind + Bats, 93 tests) wired into CI (nightly + on-demand)
- [x] First-party GitHub Action for CI manifest scanning (Phase 6 pull-forward)
- [x] Release pipeline pinning: action SHAs, gitleaks 8.30.1 (checksum-verified), GoReleaser 2.16.0
- [x] Homebrew tap token wiring; prerelease-safe publish guards; krew manifest regeneration script
- [x] Documentation Gates and Secrets Scan added to required status checks
- [x] Artifact size budget declared (Annex §8.2)

### Release execution (completed at tag time)

- [x] `v1.0.0` tag cut (signed, commit `c7cde1a`), release workflow green (run 28771164525), GitHub Release published
- [x] Homebrew tap serves `1.0.0` (stale duplicate formula removed); krew manifest regenerated with v1.0.0 checksums
- [x] Artifacts verified: Cosign checksums signature "Verified OK", checksum match, 5 SBOMs present, smoke tests pass against the shipped binary
- [x] `Release-Evidence-v1.0.0.md` filed against the real published artifacts
- [ ] GHCR package visibility → **public**: one remaining maintainer one-click (Settings → Packages → `kubevigil`). The image, its Cosign signature, and SLSA provenance are already published; only registry visibility is pending. Tracked in the release evidence checklist.

## Phase 4 — Charter Compliance

### Acceptance criteria

- [x] Charter Compliance Annex filed with public release profile
- [x] Master reference, testing strategy, waiver register, ADRs, audit closeout
- [x] `make all` enforces 96% coverage and full gate set (including `doc-gate`, `doc-drift-gate`, `doc-samples-test`, `doc-a11y`)
- [x] CI mirrors `make coverage` and documentation gates
- [x] Developer and user doc gates (`doc-gate`, `doc-drift-gate`, `doc-samples-test`)
- [x] Threat model and security ADRs published
- [x] No regression in golden scan → fix → re-scan workflow

### Quality gates (phase closeout)

```bash
make all   # includes doc-gate, doc-drift-gate, doc-samples-test, doc-a11y
```

### Dependencies

None blocking — documentation and gate wiring only; code changes limited to coverage and flaky-test fixes.

### Out of scope

- Rewriting checker registry or report HTML implementation
- New security checks beyond compliance-driven test coverage
- Hosted service / operational delivery artifacts

## 1. Revision History

| Version | Revision | Date | Change |
|---------|----------|------|--------|
| 1.0.0 | 1 | 2026-07-02 | Initial build plan; Phase 4 charter compliance in progress. |
| 1.1.0 | 2 | 2026-07-06 | Phase 4 marked complete; Phase 5 (v1.0.0 hardening + release engineering) recorded. |