---
title: "KubeVigil Threat Model"
created: 2026-07-02
updated: 2026-07-02
type: project/threat-model
status: governing-reference
tags: [charter, governance, kubevigil, security, stride]
project: kubevigil
version: "1.0.0"
revision: 1
last_updated: 2026-07-02
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
4. **MCP host → stdio MCP** — AI harness sends tool arguments

## 3. STRIDE Summary

| Threat | Example | Control |
|--------|---------|---------|
| Spoofing | Fake kubeconfig server | TLS + operator verifies cluster context |
| Tampering | Symlink escape on fix path | `os.Lstat`, `filepath.Rel` boundary checks |
| Repudiation | Deny destructive fix | Backup dir + RESTORE.md; audit logs via slog |
| Information disclosure | Secrets in scan output | `.gitignore` scan-results; operator redaction |
| Denial of service | YAML bomb / huge files | 10 MiB file limit, 10k document cap |
| Elevation of privilege | Write outside target dir | Backup path enforcement, no cluster apply |

## 4. Attack Surfaces

| Surface | Reachability | Tests |
|---------|--------------|-------|
| `kubevigil scan -f` | Local/CI | Integration + path validation |
| `kubevigil fix --apply` | Local/CI | Fix integration, symlink tests |
| `kubevigil mcp-server` | IDE agents | `internal/mcp/e2e_test.go` |
| Container image | Pull from ghcr.io | Distroless non-root, minimal base |

## 5. Residual Risks

- Operator runs fix on production git branch without review — **mitigated by dry-run default**
- Compromised dependency in build chain — **mitigated by govulncheck CI + pinned go.sum**
- Stale kubeconfig with excessive RBAC — **out of scope; operator responsibility**

## 6. Maintenance Triggers

Update this model when adding: new MCP tools, network calls, cluster write paths, or new parsers.