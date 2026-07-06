---
title: "KubeVigil Threat Model"
created: 2026-07-02
updated: 2026-07-06
type: project/threat-model
status: governing-reference
tags: [charter, governance, kubevigil, security, stride]
project: kubevigil
version: "1.5.0"
revision: 6
last_updated: 2026-07-06
parent_moc: "[[MOC - KubeVigil Governance]]"
owners: [maintainers (@msambare)]
---

# KubeVigil Threat Model

> STRIDE analysis for the KubeVigil CLI and MCP server (Security Posture Standard §2).

## 0. TL;DR

| Property | Value |
|----------|-------|
| Methodology | STRIDE |
| Assets | Operator machine, kube credentials, manifest repos, scan reports |
| Primary untrusted input | YAML manifests, file paths, MCP JSON-RPC |
| Review cadence | Each MAJOR release + after trust-boundary changes |

## 1. Assets

- Kubernetes credentials in kubeconfig (read access during live scan)
- Manifest repositories (may contain secrets; fix `--apply` writes files)
- Scan/fix reports (may echo resource names and misconfigurations)
- Local filesystem integrity (fix engine writes patches and backups)

## 2. Trust Boundaries

1. **Operator → CLI/MCP** — user invokes commands; flags and paths are attacker-controlled if malware supplies them
2. **CLI → Kubernetes API** — read-only list/get in scan; credentials scoped by kubeconfig
3. **CLI → Filesystem** — manifest read, fix write, backup directories
4. **MCP host → stdio MCP** — AI harness sends tool arguments (untrusted path input)

## 3. STRIDE Summary

| Threat | Example | Control |
|--------|---------|---------|
| Spoofing | Fake kubeconfig server | TLS + operator verifies cluster context |
| Tampering | Symlink escape on fix path | `os.Lstat`, `filepath.Rel` boundary checks |
| Repudiation | Deny destructive fix | Backup dir + RESTORE.md; audit logs via slog |
| Information disclosure | Secrets in scan output | `.gitignore` scan-results; operator redaction |
| Information disclosure (MCP egress) | Prompt injection requests `scan_manifests` on `~/.ssh/id_rsa` or repo secrets | **MCP-only** workspace confinement (`pathguard.OpenRegularWithinRoot` with `O_NOFOLLOW`, ADR-003); CLI `scan -f` is operator-trusted by design; kubeconfig symlink rejection; 10 MiB file cap |
| Denial of service | YAML bomb / huge files | 10 MiB file limit, 10k document cap |
| Elevation of privilege | Write outside target dir | Backup path enforcement, no cluster apply |

### 3.1 MCP data-egress control mapping

| Control | Implementation | Test |
|---------|----------------|------|
| Workspace root jail (MCP only) | `KUBEVIGIL_WORKSPACE_ROOT`, `--workspace-root`, `validateManifestPath` | `internal/pathguard/pathguard_test.go`, `internal/mcp/tools_scan_test.go` |
| TOCTOU symlink swap on read | Attacker replaces validated file or parent directory with symlink before read | Platform tiers: Linux `openat2(RESOLVE_NO_SYMLINKS)`; other Unix dir-fd `openat`+`O_NOFOLLOW` walk; Windows best-effort component `Lstat` walk + `SameFile` re-verification (no openat equivalent) — all read from the held handle (`OpenRegularWithinRoot`) | `TestOpenRegularWithinRoot_RejectsTOCTOUSymlinkSwap`, `TestOpenRegularWithinRoot_RejectsParentSymlinkToOutside`, `TestOpenRegularWithinRoot_RejectsConcurrentParentSymlinkSwap` |
| `..` and absolute-path escape rejection | `pathguard.ResolveWithinRoot` | `TestResolveWithinRoot_RejectsDotDotEscape` |
| Symlink traversal block | `Lstat` on entry + parent walk | `TestResolveWithinRoot_RejectsSymlinkEscape` |
| Bounded directory read | `engine.parseDirBounded` | `internal/engine/manifest_parser_bounded_test.go` |
| PII/secrets in findings payload | Severity + resource metadata only; no arbitrary file dump | MCP e2e tests; operator configures workspace to manifest tree |

## 4. Attack Surfaces

| Surface | Reachability | Tests |
|---------|--------------|-------|
| `kubevigil scan -f` | Local/CI | Integration + path validation |
| `kubevigil fix --apply` | Local/CI | Fix integration, symlink tests |
| `kubevigil mcp-server` | IDE agents | `internal/mcp/e2e_test.go`, pathguard tests |
| Container image | Pull from ghcr.io | Distroless non-root, minimal base |

## 5. Residual Risks

### 5.1 Data and Privacy (Partial applicability)

KubeVigil does not collect or persist PII. Scan and MCP outputs may **transiently surface secrets** present in operator-supplied manifests or files readable within the MCP workspace root. Controls: MCP-only workspace confinement, file size caps, operator responsibility to scope workspace to manifest trees. This is why the Data and Privacy Standard is **Partial**, not N/A — see Project Applicability Matrix and Annex §0.

- Operator runs fix on production git branch without review — **mitigated by dry-run default**
- Compromised dependency in build chain — **mitigated by govulncheck CI + pinned go.sum**
- Stale kubeconfig with excessive RBAC — **out of scope; operator responsibility**
- Backup files inherit ambient umask permissions and use predictable `<path>.kubevigil-backup-<timestamp>` names — **residual accepted**; operators should restrict backup directory permissions and treat backups as sensitive; see `internal/fix/backup.go`
- MCP kubeconfig path is not workspace-jailed (operator supplies cluster credentials by design) — **accepted**; symlink and regular-file validation only
- Custom CEL policies (v1.1.0) execute operator-supplied expressions during a scan — **accepted**; CEL is side-effect-free by construction (no I/O, no host access), expressions are compiled once and evaluated with a cost limit (`internal/policy` `evalCostLimit`) to bound CPU, per-resource evaluation errors are skipped rather than failing the scan, and policies are operator-authored (same trust level as `scan -f`). Denial-of-service from a pathological expression is bounded by the cost limit; there is no code-execution or data-egress surface.
- Windows confined-open is best-effort (`Lstat` walk + `SameFile` re-verification; no `openat`/`O_NOFOLLOW` equivalent) — **residual accepted**. Precisely: the *final* path component is re-verified with `SameFile` (narrowing its own swap window to near-zero), but *intermediate/ancestor* directories in a multi-segment path are re-resolved by path at each step and are **not** protected against a concurrent swap — an attacker with write access inside the workspace tree could redirect an ancestor directory via an NTFS junction between steps and escape confinement. Pre-planted symlinks/junctions and reparse points at any level are still correctly rejected. The Linux (`openat2 RESOLVE_NO_SYMLINKS`) and other-Unix (dir-fd `openat`+`O_NOFOLLOW`) tiers fully mitigate the ancestor race; Windows does not. Hardening (a handle-pinned or `NtCreateFile RootDirectory` walk) is tracked as backlog. This surface is reachable only via the MCP server on Windows; CLI `scan -f` is operator-trusted. The Windows implementation now has runtime test coverage in CI (`windows-pathguard` job) — previously it was only cross-compiled, never executed.

## 6. Maintenance Triggers

Update this model when adding: new MCP tools, network calls, cluster write paths, new parsers, or changes to PII/secrets leak prevention layers on `main`. The CEL policy evaluator (v1.1.0) is such a parser: revisit if the CEL environment gains new variables, functions, or any host/network access.

## 7. Revision History

| Version | Revision | Date | Change |
|---------|----------|------|--------|
| 1.0.0 | 1 | 2026-07-02 | Initial STRIDE threat model for CLI and MCP surfaces. |
| 1.1.0 | 2 | 2026-07-02 | Added MCP egress STRIDE row, control mapping, backup residual, PII-layer maintenance trigger (audit F7/F8/F24). |
| 1.2.0 | 3 | 2026-07-02 | MCP-only confinement scope, O_NOFOLLOW TOCTOU control, Data-Privacy §5.1 (audit R1/R3/R12). |
| 1.3.0 | 4 | 2026-07-06 | Windows best-effort confined-open tier documented (v1.0.0 Windows build fix); platform tiers in TOCTOU control row; Windows residual in §5.1. |
| 1.4.0 | 5 | 2026-07-06 | Precise Windows ancestor-directory TOCTOU residual (red-team); noted Windows runtime CI coverage (windows-pathguard job). |
| 1.5.0 | 6 | 2026-07-06 | Custom CEL policy evaluator residual (v1.1.0): side-effect-free, cost-limited, operator-authored — no code-exec/egress surface. |
