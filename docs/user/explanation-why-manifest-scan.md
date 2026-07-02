---
title: "Explanation — Why Manifest Scanning?"
audience: operator
created: 2026-07-02
updated: 2026-07-02
last_updated: 2026-07-02
aliases: [why-manifest-scan, manifest-vs-live]
type: project/user-explanation
status: review-draft
tags: [kubevigil, explanation, scanning, gitops]
version: "1.0.0"
revision: 1
project: kubevigil
parent_moc: "[[MOC - KubeVigil User Documentation]]"
owners: [maintainers (@msambare)]
---

# Explanation — Why Manifest Scanning?

KubeVigil supports two scan modes: **live cluster** (`kubevigil scan` with kubeconfig) and **manifest** (`kubevigil scan -f`). This document explains why manifest scanning exists and when to prefer it.

## The core idea

A live cluster shows **what is running now**. Git (or your manifest repo) shows **what you intend to run**. Security policy is often written against intent — before `kubectl apply` or a GitOps sync promotes change.

Manifest scanning lets you:

1. **Shift left** — catch misconfigurations in PRs and local edits
2. **Avoid cluster credentials in CI** — no kubeconfig secret required for static checks
3. **Match GitOps workflows** — scan the same files Argo CD or Flux will apply

## What manifest scans can see

Manifest mode loads YAML into an in-memory resource cache and runs checks registered for `ScanModeManifest`. These include workload hardening, RBAC in committed YAML, network policies declared in files, and many supply-chain annotations.

## What manifest scans cannot see

Some checks need the **live API server** or node state: admission controller configuration, running pod security admission enforcement, cloud metadata endpoints on nodes, and resources not yet committed to Git. Use live cluster scanning for those.

| Signal | Manifest scan | Live scan |
|--------|---------------|-----------|
| `privileged: true` in Deployment YAML | Yes | Yes |
| PSA enforcement on namespace | Partial (labels only) | Yes |
| API server anonymous auth | No | Yes |
| Image running vs image in YAML | No | Yes (image checks) |

## Trust model difference

- **CLI manifest paths** — operator-trusted; KubeVigil reads whatever path you pass (CI job, laptop).
- **MCP manifest paths** — AI-harness untrusted; MCP server confines reads to a configured workspace root (see `docs/mcp-setup.md`).

## When to use each mode

**Prefer manifest scanning when:**

- Gating pull requests before merge
- Auditing Helm/Kustomize output in CI
- Developers lack production cluster access

**Prefer live scanning when:**

- Validating drift between Git and cluster
- Running checks that need node or control-plane state
- Pre-release verification in staging clusters

## Related reading

- [Tutorial — first scan](tutorial-first-scan.md)
- [Manifest scanning](../scanning/manifest-scanning.md)
- [Live cluster scanning](../scanning/live-cluster.md)

## Revision History

| Revision | Date | Author | Change |
|----------|------|--------|--------|
| 1 | 2026-07-02 | maintainers | Initial Diátaxis explanation (audit F18). |