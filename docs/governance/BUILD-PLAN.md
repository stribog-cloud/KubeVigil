---
title: "KubeVigil Build Plan"
created: 2026-07-02
updated: 2026-07-06
type: project/build-plan
status: governing-reference
tags: [charter, governance, kubevigil, build-plan]
project: kubevigil
version: "1.3.0"
revision: 4
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
| 6 | v1.1.0 platform features (CEL custom policies, baseline/drift) | Complete (v1.1.0) |
| 7 | v1.2.0 runtime: validating admission webhook | Complete (v1.2.0) |
| 8 | v1.3.0 detection breadth: 40 new checks (110 → 150) | Complete (v1.3.0) |

## Phase 8 — v1.3.0 Detection Breadth (40 new checks, 110 → 150)

Widens native coverage into the gaps a scan of a modern cluster leaves open:
RBAC escalation paths, the Gateway API, admission-controller configuration, CRD
hardening, and secret hygiene. No new subsystem — every check is a standard
`checker.Checker` flowing through the existing registry, severity map,
exemptions, frameworks, and all 8 report formats.

- [x] 40 new checks across 9 categories (RBAC 15→22, Network 12→18, Cluster
      10→15, CRD 4→7, Workload 24→30, Storage 5→9, Scheduling 8→11, Secrets
      7→12, Supply Chain & Lifecycle 6→7), each with a 15+-case table-driven test
      and passing/failing fixtures; `list checks` reports `Total: 150 checks`.
      (Pre-v1.3 workload/supply-chain counts corrected against the binary — the
      earlier docs mis-split the Lifecycle sub-category.)
- [x] Severity map + MCP catalogue completeness invariants restored (40 entries);
      framework mappings added where a real published control exists (+22 MITRE,
      +5 CIS, +13 NSA) — one fabricated CIS id rejected rather than shipped, and
      `TestScanManifest_FrameworksAttached` relaxed to assert the attachment
      mechanism rather than fabricate control IDs for unmapped checks.
- [x] MITRE mapped-control count 29 → 34; HTML golden regenerated to match.
- [x] Roster tests updated (150 count + names); coverage floor held; docs,
      public-surface anchor, and governance references updated to 150.

## Phase 7 — v1.2.0 Runtime (validating admission webhook)

Turns KubeVigil from an auditor into an admission gate. `kubevigil webhook`
serves a ValidatingAdmissionWebhook that runs the same 150 checks + custom CEL
policies against each admitted object, denying findings at or above `--fail-on`
and warning below.

- [x] `engine.ScanObject`: single-object scan through the identical pipeline.
- [x] `internal/webhook`: AdmissionReview v1 handler (fail-open, read-only,
      3 MiB cap, per-object timeout), TLS server + /healthz, graceful shutdown;
      99% coverage incl. an end-to-end HTTPS round-trip and a real-engine
      integration test.
- [x] `kubevigil webhook` command; `deploy/webhook/` manifests + TLS guide.
- [x] `internal/webhook` at the 96% per-package floor; threat model rev 7
      (API-server trust boundary, DoS/tamper rows, fail-open residual).

## Phase 6 — v1.1.0 Platform Features (CEL policies + baseline/drift)

Extends KubeVigil beyond built-in checks toward commercial-KSPM parity, without
a database or a fork. Both features are opt-in and flow through the existing
scan pipeline unchanged.

- [x] `internal/policy`: CEL custom policy engine — operator-authored checks
      compile to `checker.Checker`, run via the same registry/scanner, and
      inherit severity/exemptions/frameworks/formats. `policy validate|list`
      commands; `scan --policy-file`; `customPolicies:` config block.
- [x] `internal/baseline`: portable JSON baseline; `scan --save-baseline`,
      `--baseline`, `--fail-on-new`; stable finding fingerprint; `Finding.Status`.
- [x] Both new packages enforced at the 96% per-package coverage floor.
- [x] CEL findings pass the checker contract test; exemptions verified to apply.
- [x] Threat model rev 6 (CEL evaluator residual); public-surface.md updated.
- [x] Comprehensive user docs (`docs/policies/`), e2e Bats coverage.

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
- [x] GHCR package visibility → **public** (after enabling public packages in the org policy); anonymous pull/run + Cosign + SLSA provenance all verify.

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
| 1.2.0 | 3 | 2026-07-06 | Phase 6 (v1.1.0 CEL policies + baseline/drift) recorded complete. |
| 1.3.0 | 4 | 2026-07-06 | Phase 7 (v1.2.0 admission webhook) recorded complete. |
| 1.4.0 | 5 | 2026-07-06 | Phase 8 (v1.3.0 detection breadth — 40 new checks, 110 → 150) recorded complete. |
