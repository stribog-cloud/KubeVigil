---
title: "KubeVigil Master Reference"
created: 2026-07-02
updated: 2026-07-02
type: project/master-reference
status: governing-reference
tags: [charter, governance, kubevigil, k8s, security]
project: kubevigil
version: "1.0.0"
revision: 1
last_updated: 2026-07-02
parent_moc: "[[MOC - KubeVigil Governance]]"
---

# KubeVigil — Master Reference

> Kubernetes Security Posture Management CLI — 110 checks, 8 report formats, manifest-safe auto-fix, MCP integration.

## 0. TL;DR

| Property | Value |
|----------|-------|
| Primary problem | Detect Kubernetes misconfigurations before exploitation |
| Posture | Single-binary CLI + stdio MCP server |
| Source of truth | This document + `docs/governance/`; code implements contracts |
| Language | Go 1.25+ |
| Delivery | Tagged releases (GoReleaser), Homebrew, Krew, container |
| Current phase | Phase 4 — charter compliance (v0.5.0 feature-complete) |
| Pinned charter | See `docs/governance/Charter-Compliance-Annex.md` |

KubeVigil scans live clusters or static YAML manifests, maps findings to CIS/MITRE/NSA frameworks, and optionally patches manifests with comment-preserving YAML edits. It never mutates live cluster state.

## 0.1 Current State

- **110 checks** across 12 categories (v0.5.0)
- **8 output formats:** text, json, yaml, markdown, html, sarif, junit, csv
- **Fix engine:** five-ring safety model, dry-run default, mandatory backup on `--apply`
- **MCP:** `kubevigil mcp-server` — scan, findings, summary tools
- **Coverage:** 96% floor on `internal/` + `cmd/`

## 0.2 Staff-Engineer Revisions

- **Thin CLI over shared core:** `cmd/kubevigil` delegates to `internal/engine`, `internal/fix`, `internal/report` (Charter §3.3).
- **No live patching:** fix emits artifacts only — eliminates cluster blast-radius (ADR-001).
- **yaml.v3 Node API for fixes:** preserves comments and formatting; structs are for scan, not patch (ADR-002).
- **Checker registry via init():** blank imports register checkers; contract tests enforce seam stability.

## 0.3 Charter Compliance

| Property | Value |
|----------|-------|
| Annex | `docs/governance/Charter-Compliance-Annex.md` |
| Tier | Reference |
| Waivers | `docs/governance/WAIVER-REGISTER.md` |

## 1. Trust Boundaries

| Boundary | Trusted | Untrusted |
|----------|---------|-----------|
| Input | Operator-supplied kubeconfig (explicit) | Manifest paths, MCP JSON args, YAML content |
| Execution | Local process | Remote cluster APIs (read-only in scan) |
| Output | stdout/stderr/files chosen by operator | Downstream CI parsers |

See `docs/governance/threat-model.md` for STRIDE analysis.

## 2. System Architecture

```d2
direction: right

cli: CLI / MCP {shape: rectangle}
engine: Scan Engine {shape: rectangle}
checkers: Checker Registry (110) {shape: rectangle}
fix: Fix Engine {shape: rectangle}
report: Reporters (8) {shape: rectangle}

cli -> engine: scan
cli -> fix: fix manifests
engine -> checkers: ResourceCache
checkers -> report: ScanResult
fix -> engine: re-scan verify
```

Source: `docs/governance/diagrams/src/architecture.d2`

### Package layout

- `cmd/kubevigil/` — Cobra commands (scan, fix, list, mcp-server, version)
- `internal/checker/` — Checker interface, registry, 12 category packages
- `internal/engine/` — Scan orchestration, manifest parsing
- `internal/fix/` — Remediation engine, YAML patcher, backup
- `internal/report/` — Output formatters
- `internal/mcp/` — MCP tool handlers
- `internal/k8s/` — Client construction, namespace filters
- `internal/config/` — `.kubevigil.yaml`, exemptions
- `internal/frameworks/` — CIS, MITRE, NSA mappings

Contributor detail: `docs/dev/architecture.md` (derived from this reference).

## 3. Scan Pipeline

Discover → Run checks (errgroup) → Post-process (severity, exemptions, frameworks) → Render report.

## 4. Fix Pipeline

Scan → Filter → Classify → Gate (risk/system/known workload) → Plan → Backup → Patch → Verify.

## 5. Non-Goals

- Agent/sidecar deployment in cluster
- Direct API writes to running clusters
- Policy-as-code engine (OPA/Gatekeeper replacement)

## 6. Open Risks

| Risk | Mitigation | Status |
|------|------------|--------|
| Untrusted YAML bombs | Size/count limits in engine and fix parsers | Mitigated v0.5.0 |
| Symlink escape on fix paths | `os.Lstat` boundary checks | Mitigated v0.5.0 |
| MCP path injection | Validation + length limits | Mitigated v0.5.0 |

## 7. Revision History

| Version | Date | Change |
|---------|------|--------|
| 1.0.0 | 2026-07-02 | Initial master reference for charter compliance |