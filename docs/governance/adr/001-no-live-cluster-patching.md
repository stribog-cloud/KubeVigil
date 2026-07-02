---
title: "ADR-001 No Live Cluster Patching"
created: 2026-07-02
updated: 2026-07-02
type: project/adr
adr_status: accepted
status: governing-reference
tags: [adr, kubevigil, safety]
project: kubevigil
version: "1.0.0"
revision: 2
last_updated: 2026-07-02
parent_moc: "[[MOC - KubeVigil Governance]]"
owners: [maintainers (@msambare)]
---

# ADR-001: No Live Cluster Patching

## adr_status

accepted

## Status

Accepted

## Context

KubeVigil can remediate misconfigurations. Applying changes directly to a live cluster creates irreversible blast radius and bypasses GitOps review.

## Decision

The fix command only modifies local manifest files or emits kubectl/Helm/Kustomize artifacts. No Kubernetes write API calls.

## Alternatives Considered

| Option | Outcome |
|--------|---------|
| Do nothing (allow live apply) | Rejected — violates Safety by Design; operators lose audit trail |
| Opt-in `--apply-to-cluster` flag | Rejected — footgun surface; deferred indefinitely |
| Local manifest / artifact only (chosen) | Aligns with GitOps; SAR Safety by Design §3.5 |

## Forces

- Operators expect reviewable, reversible changes in version control
- Live mutation requires cluster-admin credentials KubeVigil should not consume
- Fix engine must remain testable without a running cluster

## Verification

- `internal/fix/` contains no `client-go` write calls (apply/patch/update/delete)
- Integration tests apply fixes only to fixture files under `test/fixtures/fix/`
- Threat model EoP row documents no cluster write path

## Consequences

- Operators must review and apply changes through their GitOps pipeline
- Eliminates entire class of accidental production mutation incidents
- SAR alignment: Safety by Design (Engineering Charter §3.5)

## Revision History

| Revision | Date | Author | Change |
|----------|------|--------|--------|
| 1 | 2026-07-02 | maintainers | Initial ADR filed during charter compliance program. |
| 2 | 2026-07-02 | maintainers | Added mandatory template fields: Alternatives, Forces, Verification (audit F16). |