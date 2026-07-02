---
title: "KubeVigil Waiver Register"
created: 2026-07-02
updated: 2026-07-02
type: project/waiver-register
status: governing-reference
tags: [charter, governance, kubevigil, waiver]
project: kubevigil
version: "1.1.0"
revision: 2
last_updated: 2026-07-02
parent_moc: "[[MOC - KubeVigil Governance]]"
owners: [maintainers (@msambare)]
---

# KubeVigil Waiver Register

> Authoritative record of charter waivers. Empty register is compliant; absent register is not.

## Active Waivers

| Waiver ID | Clause | Scope | Owner | Expiry | Compensating controls |
|-----------|--------|-------|-------|--------|---------------------|
| — | — | — | — | — | — |

**No active waivers as of revision 2.**

### Waived-risk disposition (audit F1/F7)

The prior MCP arbitrary-path read risk (F1) is **not waived** — it was remediated on branch `charter-compliance` via workspace root confinement (ADR-003, `internal/pathguard`). No waiver entry is required because the residual is mitigated, not deferred. See threat model §3.1 for control mapping.

## Closed Waivers

| Waiver ID | Clause | Closed | Notes |
|-----------|--------|--------|-------|
| — | — | — | — |

## Revision History

| Version | Revision | Date | Change |
|---------|----------|------|--------|
| 1.0.0 | 1 | 2026-07-02 | Initial empty waiver register filed. |
| 1.1.0 | 2 | 2026-07-02 | Documented why MCP path-confinement needs no waiver after remediation (audit F7). |