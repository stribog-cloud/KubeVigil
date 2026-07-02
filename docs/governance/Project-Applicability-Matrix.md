---
title: "KubeVigil — Project Applicability Matrix"
created: 2026-07-02
updated: 2026-07-02
type: stribog/applicability-matrix
status: governing-reference
tags: [stribog, compliance, applicability, kubevigil, governance]
version: "0.1.0"
revision: 1
project: kubevigil
last_updated: 2026-07-02
parent_moc: "[[MOC - KubeVigil Governance]]"
owners: [maintainers (@msambare)]
---

# KubeVigil — Project Applicability Matrix

Maps each Stribog governing standard to its applicability for KubeVigil. Derived from the project profile declared in Charter Compliance Annex §0 (Engineering Charter §0.4) and the Reference compliance tier (Engineering Charter §0.6).

**Project profile (Charter §0.4):** public library / package (CLI binary + MCP server)

**Compliance tier (Charter §0.6):** Reference

Review this matrix at every charter version bump. A change to any row is a Compliance-Annex change governed by Charter Governance §6.

---

## Applicability Matrix

| Standard | Applicability | Rationale |
|---|---|---|
| Universal Stribog Engineering Charter | `bound` | Binds every Stribog project per §0.2. |
| Stribog Documentation Standard | `bound` | Binds every governing/reference/plan/audit document in `docs/governance/`. |
| Stribog AI Agent Execution Standard | `bound` | AI-assisted contribution is permitted; agents must follow Annex reading order and attribution rules. |
| Stribog Operational Delivery Standard | `not applicable` | CLI-only product; no managed-service or rolling-deployment scope. |
| Stribog Security Posture Standard | `bound` | Security tool with untrusted manifest input, MCP channel, and filesystem side effects. |
| Stribog Data and Privacy Standard | `partial` | No persistent PII store; MCP/scan may transiently surface secrets from operator-supplied paths within workspace confinement. See threat model §5 and Annex §0.1. |
| Stribog User Documentation Standard | `bound` | Operator/integrator CLI and MCP surface consumed by non-engineers. |
| Stribog Developer Documentation Standard | `bound` | Public Go module, MCP schemas, and contributor onboarding. |
| Stribog UI/UX Standard | `not applicable` | Line-oriented CLI per UI/UX Standard §0.2; no graphical UI. |
| Stribog Glossary | `bound` | Shared vocabulary for governance and contributor docs. |
| Charter Governance | `bound` | Governs charter pins, waivers, audits, and public release profile. |

**Applicability values:**

- `bound` — standard applies in full per its §0.2 criteria; posture declared in Charter Compliance Annex.
- `not applicable` — standard's §0.2 criteria are not met; rationale recorded above.
- `waivered` — standard applies but a specific clause is waived; waiver recorded in the Waiver Register.

---

## Active Waivers

No active waivers.

---

## Review History

| Version | Revision | Date | Reviewer | Change |
|---------|----------|------|----------|--------|
| 0.1.0 | 1 | 2026-07-02 | maintainers (@msambare) | Initial matrix filed from Stribog template. Closes audit finding F11. |

## Revision History

| Version | Revision | Date | Change |
|---------|----------|------|--------|
| 0.1.0 | 1 | 2026-07-02 | Initial filing from `templates/Project-Applicability-Matrix-Template.md`. |