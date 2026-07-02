---
title: "ADR-003 MCP Workspace Path Confinement"
created: 2026-07-02
updated: 2026-07-02
last_updated: 2026-07-02
type: project/adr
adr_status: accepted
status: governing-reference
tags: [adr, kubevigil, security, mcp]
project: kubevigil
version: "2.0.0"
revision: 3
owners: [maintainers (@msambare)]
parent_moc: "[[MOC - KubeVigil Governance]]"
---

# ADR-003: MCP Workspace Path Confinement

## adr_status

accepted

## Status

Accepted — implemented on branch `charter-compliance` (not v0.5.0 retroactive credit).

## Context

MCP `scan_manifests` accepts filesystem paths from AI agents — untrusted input per Security Posture Standard. Prior code rejected symlinks and validated existence but allowed arbitrary absolute paths readable by the OS user, enabling data egress via prompt injection.

## Decision

Confine MCP manifest scans to an explicit workspace root:

- Default root: `KUBEVIGIL_WORKSPACE_ROOT` or process cwd at server start; override via `kubevigil mcp-server --workspace-root`
- `internal/pathguard.ResolveWithinRoot` rejects `..` escape, paths outside root, and symlink traversal (including parent symlinks)
- `pathguard.OpenRegularWithinRoot` opens with `O_NOFOLLOW` and reads from the held fd — prevents TOCTOU symlink swap between validate and read
- `validateManifestPath` and `engine.ParsePathWithinRoot` enforce the boundary on the **MCP surface only**
- CLI `scan -f` and `fix` remain unrestricted (operator-trusted paths by design; G304 nolint documents this)
- Integrators **must** set an explicit narrow `--workspace-root` (or `KUBEVIGIL_WORKSPACE_ROOT`); default cwd is unsafe when the server starts from `$HOME` or `/`

## Alternatives Considered

| Option | Outcome |
|--------|---------|
| Do nothing (defer confinement) | Rejected — live egress risk on MCP channel |
| Symlink-only checks (v0.5.0 state) | Insufficient — absolute paths still readable |
| Workspace confinement (chosen) | Matches MCP local-server threat model with configurable root |

## Forces

- MCP clients are untrusted; operators may point workspace at a repo checkout
- CLI scans must not regress for CI/CD absolute paths
- TOCTOU: `O_NOFOLLOW` fd open after path resolution; no `os.ReadFile` re-resolution on confined paths

## Verification

- `internal/pathguard/pathguard_test.go` — outside root, `..`, symlink escape rejected
- `internal/mcp/tools_scan_test.go` — `TestValidateManifestPath_RejectsOutsideWorkspace`
- `go test ./internal/pathguard/... ./internal/mcp/... ./internal/engine/...`

## Consequences

- MCP manifest scans outside workspace fail fast with explicit error
- Integrators must set workspace root to their manifest tree
- ADR-001 symlink checks remain complementary, not sufficient alone

## Revision History

| Revision | Date | Author | Change |
|----------|------|--------|--------|
| 1 | 2026-07-02 | maintainers | Initial ADR (incorrectly credited v0.5.0 hardening) |
| 2 | 2026-07-02 | maintainers | Rewritten after adversarial audit F1 — documents workspace confinement on this branch |
| 3 | 2026-07-02 | maintainers | O_NOFOLLOW fd reads (R1 TOCTOU); explicit MCP-only scope and workspace-root guidance (R12/R10) |